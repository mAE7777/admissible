from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Protocol

import httpx

from cloak.models import PatchProposal
from cloak.privacy import TOKEN_PATTERN, repair_sentence_replacement

REPLACEMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "replacement": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["replacement", "rationale"],
}
UNIQUENESS_MARKERS = {
    "first",
    "only",
    "youngest",
    "oldest",
    "earliest",
    "latest",
    "highest",
    "lowest",
    "sole",
}
DEMOGRAPHIC_MARKERS = {"woman", "women", "female", "man", "men", "male"}
REVISION_GENERIC_WORDS = {
    "activity",
    "after",
    "before",
    "broad",
    "completed",
    "different",
    "education",
    "earlier",
    "experience",
    "experiences",
    "family",
    "field",
    "general",
    "individual",
    "institution",
    "joined",
    "later",
    "multiple",
    "organization",
    "person",
    "professional",
    "project",
    "public",
    "received",
    "role",
    "settings",
    "studied",
    "subject",
    "their",
    "they",
    "training",
    "used",
    "various",
    "work",
    "worked",
    "wrote",
}


class LocalAnonymizer(Protocol):
    async def propose_patch(
        self,
        candidate: str,
        evidence_quote: str,
        prior_replacement: str | None = None,
        task: str = "",
        protected_facts: list[str] | None = None,
    ) -> PatchProposal: ...

    async def ready(self) -> bool: ...


class OllamaAnonymizer:
    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 40.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL") or "qwen3.5:4b"
        self.timeout_seconds = timeout_seconds

    async def ready(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                names = {item["name"] for item in response.json().get("models", [])}
                return self.model in names
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return False

    async def propose_patch(
        self,
        candidate: str,
        evidence_quote: str,
        prior_replacement: str | None = None,
        task: str = "",
        protected_facts: list[str] | None = None,
    ) -> PatchProposal:
        del candidate  # The model receives only the grounded clue, never a rewriteable document.
        feedback = ""
        last_reason = "no valid response"
        required_facts = protected_facts or []
        authorized_text = prior_replacement or evidence_quote
        revision_forbidden: list[str] = []
        if prior_replacement is not None:
            original_words = set(re.findall(r"[a-z]+", TOKEN_PATTERN.sub("", evidence_quote).casefold()))
            prior_words = set(re.findall(r"[a-z]+", TOKEN_PATTERN.sub("", prior_replacement).casefold()))
            revision_forbidden = sorted(
                word
                for word in original_words - prior_words
                if len(word) >= 4 and word not in REVISION_GENERIC_WORDS
            )
        sentence_clue = authorized_text.strip().endswith((".", "!", "?"))
        shape_instruction = (
            "Return a short complete sentence with an explicit grammatical subject, sentence-case "
            "capitalization, and ending punctuation. Prefer 'The subject' over a gendered pronoun."
            if sentence_clue
            else "Return only a short phrase that can replace EXACT_CLUE."
        )
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for _attempt in range(2):
                prompt = (
                    f"{shape_instruction} Make a surgical privacy edit to ORIGINAL_CLUE while preserving the "
                    "downstream TASK. Remove or generalize only identity-bearing detail while preserving "
                    "amounts, dates, chronology, roles, event direction, direct statements, and categories when "
                    "the task needs them. Every REQUIRED_FACT must remain byte-for-byte in the replacement. "
                    "The controller handles proper-entity substitution before this call, so do not invent names "
                    "or delete task facts. A multi-fact "
                    "sentence should remain a broader multi-fact sentence, not collapse into an award or job that "
                    "was never stated. Outside REQUIRED_FACTS, make residual identity detail broad enough to fit "
                    "thousands of people. Remove first, only, youngest, oldest, "
                    "exact ranks, and demographic "
                    "uniqueness rather than rephrasing them. The replacement must be 3 to 24 words. Do "
                    "not return a document, prefix, label, or surrounding context. Do not add facts. Copy every "
                    "locally generated replacement listed in REQUIRED_FACTS byte-for-byte. Keep rationale under "
                    "15 words. "
                    "Example: for 'first woman "
                    "to receive "
                    "the Fields Medal', use 'received a major mathematics award'; never use 'first "
                    "female', 'earliest woman', or 'highest math award'. For a full sentence, use 'The subject "
                    "received a major mathematics award.' Generalize at least two levels: use 'a broad regional "
                    "setting', never a country; 'personal interests', never a named sport or 'sports'; 'a technical "
                    "field', never a discipline; 'an organization', never an industry or company type; and 'a "
                    "project', never a product category."
                    + (
                        " PREVIOUS_REPLACEMENT was still sufficient for re-identification. Return a materially "
                        "broader replacement for PREVIOUS_REPLACEMENT while preserving only the broad action or "
                        "relationship from ORIGINAL_CLUE. Do not reuse its domain, geography, institution type, "
                        "industry, activity type, or career stage. Never output these removed source terms: "
                        f"{', '.join(revision_forbidden)}."
                        if prior_replacement
                        else ""
                    )
                    + feedback
                    + f"\n\nTASK:\n{task or 'Preserve the document\'s substantive meaning.'}"
                    + "\n\nREQUIRED_FACTS:\n"
                    + ("\n".join(f"- {fact}" for fact in required_facts) if required_facts else "- none")
                    + f"\n\nORIGINAL_CLUE:\n{evidence_quote}"
                    + (
                        f"\n\nPREVIOUS_REPLACEMENT:\n{prior_replacement}"
                        if prior_replacement
                        else ""
                    )
                )
                payload = {
                    "model": self.model,
                    "stream": False,
                    "think": False,
                    "keep_alive": "10m",
                    "messages": [{"role": "user", "content": prompt}],
                    "format": REPLACEMENT_SCHEMA,
                    "options": {"temperature": 0, "num_predict": 90},
                }
                try:
                    response = await client.post(f"{self.base_url}/api/chat", json=payload)
                    response.raise_for_status()
                    content = response.json()["message"]["content"]
                    raw = json.loads(content)
                    if not isinstance(raw, dict):
                        raise ValueError("non-object payload")
                    replacement = " ".join(str(raw.get("replacement", "")).split())
                    replacement = repair_sentence_replacement(authorized_text, replacement)
                    reason = self._replacement_error(authorized_text, replacement, [])
                    if not reason:
                        lost_facts = [fact for fact in required_facts if fact not in replacement]
                        if lost_facts:
                            reason = f"replacement removes required fact ({lost_facts[0]})"
                    if not reason and prior_replacement is not None:
                        reason = self._revision_error(evidence_quote, prior_replacement, replacement)
                    if reason:
                        last_reason = reason
                        feedback = f"\nPrevious proposal was invalid ({reason}). Return a different phrase."
                        continue
                    rationale = str(raw.get("rationale", "Minimal clue generalization."))[:300]
                    return PatchProposal(
                        old_text=authorized_text,
                        replacement=replacement,
                        rationale=rationale,
                    )
                except httpx.HTTPStatusError as exc:
                    detail = exc.response.text[:500]
                    raise RuntimeError(f"Local anonymizer returned HTTP {exc.response.status_code}: {detail}") from exc
                except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                    raise RuntimeError(f"Local anonymizer failed: {type(exc).__name__}") from exc
        raise RuntimeError(f"Local anonymizer could not produce a bounded replacement in two attempts: {last_reason}.")

    @staticmethod
    def _replacement_error(evidence_quote: str, replacement: str, tokenize_values: list[str]) -> str | None:
        if not replacement or (replacement == evidence_quote and not tokenize_values):
            return "empty or unchanged"
        for value in tokenize_values:
            if value not in evidence_quote or value not in replacement:
                return "token value must occur exactly in the clue and replacement"
            if len(value) > 80 or not re.search(r"[A-Za-z]", value) or re.search(r"\d", value):
                return "token values must be short proper-name text"
        if Counter(TOKEN_PATTERN.findall(replacement)) != Counter(TOKEN_PATTERN.findall(evidence_quote)):
            return "opaque token mismatch"
        word_count = len(re.findall(r"[\w'-]+", TOKEN_PATTERN.sub("", replacement)))
        if not 3 <= word_count <= 24:
            return "replacement must contain 3 to 24 words"
        plain_replacement = TOKEN_PATTERN.sub("", replacement)
        for value in tokenize_values:
            plain_replacement = plain_replacement.replace(value, "")
        words = re.findall(r"\b[A-Za-z][A-Za-z'-]*\b", plain_replacement)
        evidence_words_with_case = set(re.findall(r"\b[A-Za-z][A-Za-z'-]*\b", evidence_quote))
        first_allowed = 1 if evidence_quote.strip().endswith((".", "!", "?")) else 0
        for index, word in enumerate(words):
            if index < first_allowed:
                continue
            if (len(word) > 1 and word.isupper()) or (word[0].isupper() and word[1:].islower()):
                if tokenize_values and word in evidence_words_with_case:
                    continue
                return "replacement introduces a proper name or acronym"
        if evidence_quote.strip().endswith((".", "!", "?")):
            if not replacement.strip().endswith((".", "!", "?")):
                return "preserve sentence-ending punctuation"
            first_letter = next((character for character in replacement if character.isalpha()), "")
            if first_letter and not first_letter.isupper():
                return "preserve sentence-initial capitalization"
        evidence_words = set(re.findall(r"[a-z]+", evidence_quote.casefold()))
        replacement_words = set(re.findall(r"[a-z]+", replacement.casefold()))
        if evidence_words & UNIQUENESS_MARKERS:
            if replacement_words & (UNIQUENESS_MARKERS | DEMOGRAPHIC_MARKERS):
                return "remove all uniqueness and demographic markers"
        if len(replacement) > 180:
            return "replacement is too long"
        return None

    @staticmethod
    def _revision_error(original_clue: str, prior_replacement: str, replacement: str) -> str | None:
        def words(value: str) -> set[str]:
            return set(re.findall(r"[a-z]+", TOKEN_PATTERN.sub("", value).casefold()))

        original_words = words(original_clue)
        prior_words = words(prior_replacement)
        replacement_words = words(replacement)
        removed_specifics = {
            word
            for word in original_words - prior_words
            if len(word) >= 4 and word not in REVISION_GENERIC_WORDS
        }
        reintroduced = sorted(removed_specifics & replacement_words)
        if reintroduced:
            return f"revision reintroduces removed source detail ({', '.join(reintroduced[:5])})"
        return None
