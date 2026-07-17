from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter

from lingua import Language, LanguageDetectorBuilder
from rapidfuzz.distance import Levenshtein

from cloak.models import GroundedEvidence, SanitizedCandidate, UtilityLedger

MAX_CODEPOINTS = 12_000
MAX_PER_PASS_EDIT_RATIO = 0.20
MAX_CUMULATIVE_EDIT_RATIO = 0.40
TOKEN_PATTERN = re.compile(r"\[\[CX_[A-Z2-7]{16}_[0-9a-f]{8}\]\]")
LOOSE_TOKEN_PATTERN = re.compile(r"\[?\[?CX_[A-Za-z0-9_-]{6,}(?:_[A-Za-z0-9]{1,12})?\]?\]?")
DETERMINERS = {"a", "an", "the", "this", "that", "these", "those"}
SUBJECT_PRONOUNS = {"he", "her", "hers", "him", "it", "she", "they", "we"}
VERBISH_SENTENCE_STARTS = {
    "became",
    "built",
    "created",
    "developed",
    "earned",
    "founded",
    "grew",
    "joined",
    "led",
    "made",
    "published",
    "received",
    "served",
    "taught",
    "won",
    "worked",
    "wrote",
}
MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
    r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)
MONEY_PATTERNS = (
    re.compile(r"(?<!\w)-?\$\d[\d,]*(?:\.\d+)?"),
    re.compile(r"\b\d+(?:\.\d+)?%"),
)
DATE_PATTERNS = (
    re.compile(rf"\b(?:[0-3]?\d\s+{MONTH}|{MONTH}\s+[0-3]?\d)(?:\s*,?\s*\d{{4}})?\b", re.IGNORECASE),
    re.compile(rf"\b{MONTH}\s+\d{{4}}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"\b(?:19|20)\d{2}\b"),
)
DURATION_PATTERN = re.compile(
    r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|\d+(?:\.\d+)?)"
    r"[- ](?:day|week|month|year|hour)s?\b",
    re.IGNORECASE,
)
CLINICAL_VALUE_PATTERN = re.compile(r"\b\d+(?:\.\d+)?\s*(?:mg|g|mcg|mL|U/L|g/dL)\b", re.IGNORECASE)
EXACT_STATEMENT_TASK_TERMS = {
    "chronology",
    "direct evidence",
    "direct observation",
    "exact context",
    "internal consistency",
    "sequence",
    "timeline",
}
EXACT_STATEMENT_TASK_MARKERS = (
    "comment",
    "exact words",
    "quote",
    "remark",
    "said",
    "statement",
    "stated",
    "told",
    "verbatim",
    "what was written",
    "wording",
    "wrote",
)
ROLE_TASK_MARKERS = (
    "duties",
    "duty",
    "fiduciar",
    "job",
    "occupation",
    "position",
    "responsibilit",
    "role",
    "title",
)
EVENT_RELATION_TASK_MARKERS = (
    " by whom",
    "caus",
    "chronology",
    "event direction",
    "reason",
    "relationship",
    "responsible",
    "sequence",
    "timeline",
    " what happened",
    " which party",
    " who ",
    " whom",
    "why",
)
STATEMENT_CUES = re.compile(
    r"\b(?:said|stated|told|reported|wrote|comment|asked that it be documented)\b",
    re.IGNORECASE,
)
ROLE_FACT_CUES = re.compile(
    r"\b(?:appointed|elected|employed|promoted|served?|serves?|worked|works?)\s+(?:as|to)\b|"
    r"\b(?:dut(?:y|ies)|fiduciar(?:y|ies)|job|occupation|position|responsibilit(?:y|ies)|role|title|trustee)\b",
    re.IGNORECASE,
)
EVENT_RELATION_CUES = re.compile(
    r"\b(?:accused|approved|assaulted|assigned|decreased|demoted|denied|dismissed|fired|hired|increased|paid|"
    r"promoted|reported|signed|stopped|struck|terminated|threatened|transferred)\b",
    re.IGNORECASE,
)
EVENT_TASK_CUES = re.compile(
    r"\b(?:accus\w*|approv\w*|assault\w*|assign\w*|decreas\w*|demot\w*|deni\w*|dismiss\w*|"
    r"fire(?:d|s|ing)?|hir\w*|increas\w*|promot\w*|signed?|signing|stop\w*|strik\w*|terminat\w*|"
    r"threat\w*|transfer\w*)\b",
    re.IGNORECASE,
)
LANGUAGE_DETECTOR = LanguageDetectorBuilder.from_all_spoken_languages().build()
SHORT_ENGLISH_TASKS = {
    "analyze",
    "build",
    "calculate",
    "check",
    "compare",
    "determine",
    "explain",
    "extract",
    "find",
    "flag",
    "identify",
    "list",
    "quote",
    "review",
    "summarise",
    "summarize",
}
PROPER_ATOM = re.compile(r"\b[A-Z][a-z]{2,}\b")
NON_IDENTITY_TITLE_WORDS = {
    "account",
    "agreement",
    "analytical",
    "available",
    "before",
    "billing",
    "cardholder",
    "clinic",
    "civic",
    "complaint",
    "confidential",
    "cooperative",
    "credit",
    "data",
    "director",
    "draft",
    "email",
    "employer",
    "energy",
    "employment",
    "ferry",
    "her",
    "hotel",
    "internal",
    "lead",
    "manager",
    "market",
    "operations",
    "patient",
    "payment",
    "product",
    "prize",
    "rail",
    "reference",
    "selected",
    "statement",
    "summary",
    "terminal",
    "this",
    "transactions",
}
NON_IDENTITY_TITLE_WORDS.update(
    {
        "jan",
        "january",
        "feb",
        "february",
        "mar",
        "march",
        "apr",
        "april",
        "may",
        "jun",
        "june",
        "jul",
        "july",
        "aug",
        "august",
        "sep",
        "september",
        "oct",
        "october",
        "nov",
        "november",
        "dec",
        "december",
    }
)


def normalize_input(text: str) -> str:
    normalized = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    if not normalized.strip():
        raise ValueError("Paste a document before continuing.")
    if len(normalized) > MAX_CODEPOINTS:
        raise ValueError(f"Documents are limited to {MAX_CODEPOINTS:,} characters in this build.")
    return normalized


def normalized_identity(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    value = re.sub(r"\s+", " ", value).strip()
    return value.strip(" \t\n\r.,;:!?()[]{}\"'“”‘’—–-")


def english_scope_supported(text: str) -> bool:
    """Enforce the English-only product scope with a fully local language identifier."""
    words = re.findall(r"[^\W\d_]+", text.casefold(), flags=re.UNICODE)
    if 1 <= len(words) <= 3 and words[0] in SHORT_ENGLISH_TASKS:
        return True
    return LANGUAGE_DETECTOR.detect_language_of(text) == Language.ENGLISH


def identity_rank(guesses: list[str], aliases: list[str]) -> int | None:
    allowed = {normalized_identity(alias) for alias in aliases if alias.strip()}
    for index, guess in enumerate(guesses[:5], start=1):
        if normalized_identity(guess) in allowed:
            return index
    return None


def deterministic_task_facts(task: str, candidate: str) -> list[str]:
    """Conservative local floor for facts whose deletion commonly makes downstream answers wrong."""
    matches: list[tuple[int, str]] = []
    normalized_task = task.casefold()
    # Structured values are always locked. Natural-language task wording is open-ended, and deleting an amount,
    # date, duration, or clinical dose can silently make an answer wrong even when the task does not use one of a
    # small curated set of keywords. This deliberately prefers an honest privacy/utility block over semantic loss.
    patterns: list[re.Pattern[str]] = [*MONEY_PATTERNS, *DATE_PATTERNS, DURATION_PATTERN, CLINICAL_VALUE_PATTERN]
    if any(term in normalized_task for term in ("amount", "fee", "financial", "interest", "payment", "utilization")):
        patterns.extend(MONEY_PATTERNS)
        patterns.extend(DATE_PATTERNS)
    if any(term in normalized_task for term in ("chronology", "date", "sequence", "timeline")):
        patterns.extend(DATE_PATTERNS)
        patterns.append(DURATION_PATTERN)
    if any(term in normalized_task for term in ("agreement", "clause", "contract", "compensation", "lease")):
        patterns.extend(MONEY_PATTERNS)
        patterns.extend(DATE_PATTERNS)
        patterns.append(DURATION_PATTERN)
    if any(term in normalized_task for term in ("condition", "medical", "medication", "monitoring", "symptom")):
        patterns.append(CLINICAL_VALUE_PATTERN)
    for pattern in dict.fromkeys(patterns):
        matches.extend((match.start(), match.group(0)) for match in pattern.finditer(candidate))

    if any(term in normalized_task for term in EXACT_STATEMENT_TASK_TERMS) or any(
        marker in normalized_task for marker in EXACT_STATEMENT_TASK_MARKERS
    ):
        for sentence_match in re.finditer(r"[^\n.!?]*(?:[.!?]|$)", candidate):
            sentence = sentence_match.group(0).strip()
            if sentence and STATEMENT_CUES.search(sentence):
                offset = sentence_match.start() + sentence_match.group(0).find(sentence)
                matches.append((offset, sentence))

    if any(marker in normalized_task for marker in ROLE_TASK_MARKERS):
        for sentence_match in re.finditer(r"[^\n.!?]*(?:[.!?]|$)", candidate):
            sentence = sentence_match.group(0).strip()
            if sentence and (ROLE_FACT_CUES.search(sentence) or TOKEN_PATTERN.search(sentence)):
                offset = sentence_match.start() + sentence_match.group(0).find(sentence)
                matches.append((offset, sentence))

    padded_task = f" {normalized_task} "
    if any(marker in padded_task for marker in EVENT_RELATION_TASK_MARKERS) or EVENT_TASK_CUES.search(normalized_task):
        for sentence_match in re.finditer(r"[^\n.!?]*(?:[.!?]|$)", candidate):
            sentence = sentence_match.group(0).strip()
            if sentence and (EVENT_RELATION_CUES.search(sentence) or TOKEN_PATTERN.search(sentence)):
                offset = sentence_match.start() + sentence_match.group(0).find(sentence)
                matches.append((offset, sentence))

    domain_line_keywords: tuple[str, ...] = ()
    if any(term in normalized_task for term in ("agreement", "clause", "contract", "lease")):
        domain_line_keywords = (
            "renew",
            "term",
            "salary",
            "bonus",
            "repay",
            "restrict",
            "compete",
            "confidential",
            "invention",
            "arbitrat",
            "dispute",
            "terminate",
            "termination",
            "severance",
            "work location",
            "reporting line",
        )
    elif any(term in normalized_task for term in ("fee", "financial", "interest", "payment", "utilization")):
        domain_line_keywords = (
            "balance",
            "credit",
            "payment",
            "purchase",
            "fee",
            "interest",
            "apr",
            "transaction",
            "—",
            "warning",
        )
    elif any(term in normalized_task for term in ("workplace", "retaliation", "discrimination", "hr or counsel")):
        domain_line_keywords = (
            "leave",
            "performance",
            "promotion",
            "manager",
            "coworker",
            "reported",
            "schedule",
            "slack",
            "warning",
            "inference",
        )
    elif any(term in normalized_task for term in ("medical", "medication", "monitoring", "specialist", "symptom")):
        domain_line_keywords = (
            "disease",
            "adalimumab",
            "screen",
            "radiograph",
            "laboratory",
            "symptom",
            "pain",
            "pregnan",
            "vaccin",
            "coordinate",
        )
    elif any(term in normalized_task for term in ("immigration", "declaration", "evidentiary")):
        domain_line_keywords = (
            "worked",
            "report",
            "threat",
            "assault",
            "police",
            "clinic",
            "moved",
            "relocat",
            "departed",
            "evidence",
            "chronology",
        )

    if domain_line_keywords:
        cursor = 0
        for raw_line in candidate.splitlines(keepends=True):
            line = raw_line.strip()
            line_start = cursor + raw_line.find(line) if line else cursor
            cursor += len(raw_line)
            if line and any(keyword in line.casefold() for keyword in domain_line_keywords):
                matches.append((line_start, line))

    ordered: list[str] = []
    for _offset, value in sorted(matches, key=lambda item: (item[0], -len(item[1]))):
        if value not in ordered:
            ordered.append(value)
    return ordered[:60]


def tokenizable_specifics(quote: str, protected_facts: list[str]) -> list[str]:
    """Find narrow proper-name atoms that can be vaulted while leaving useful categories in place."""
    protected_ranges: list[tuple[int, int]] = []
    for fact in protected_facts:
        cursor = 0
        while fact:
            start = quote.find(fact, cursor)
            if start < 0:
                break
            protected_ranges.append((start, start + len(fact)))
            cursor = start + 1

    values: list[str] = []
    for match in PROPER_ATOM.finditer(quote):
        value = match.group(0)
        if value.casefold() in NON_IDENTITY_TITLE_WORDS:
            continue
        if any(match.start() < end and match.end() > start for start, end in protected_ranges):
            continue
        values.append(value)
    return list(dict.fromkeys(values))[:10]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def candidate_from_text(
    text: str,
    *,
    original_text: str,
    pass_number: int,
    parent_sha256: str | None,
    previous_text: str | None = None,
    restore_handles: list[str] | None = None,
) -> SanitizedCandidate:
    per_pass = 0.0 if previous_text is None else Levenshtein.normalized_distance(previous_text, text)
    cumulative = Levenshtein.normalized_distance(original_text, text)
    return SanitizedCandidate(
        text=text,
        sha256=sha256_text(text),
        parent_sha256=parent_sha256,
        pass_number=pass_number,
        per_pass_edit_ratio=per_pass,
        cumulative_edit_ratio=cumulative,
        # ``token_ids`` is retained as an API compatibility name. Product candidates now carry
        # natural surrogate surfaces; the legacy opaque-token regex remains for recorded demos and
        # the intentionally naive benchmark baseline.
        token_ids=_extract_restore_handles(text, restore_handles or TOKEN_PATTERN.findall(text)),
    )


def ground_quote(candidate: str, quote: str) -> GroundedEvidence:
    if not quote:
        return GroundedEvidence(quote=quote, status="missing")
    starts: list[int] = []
    cursor = 0
    while True:
        index = candidate.find(quote, cursor)
        if index < 0:
            break
        starts.append(index)
        cursor = index + 1
    if not starts:
        return GroundedEvidence(quote=quote, status="missing")
    if len(starts) > 1:
        return GroundedEvidence(quote=quote, status="ambiguous")
    start = starts[0]
    end = start + len(quote)
    utf16_start = len(candidate[:start].encode("utf-16-le")) // 2
    utf16_end = len(candidate[:end].encode("utf-16-le")) // 2
    return GroundedEvidence(
        quote=quote,
        status="grounded",
        codepoint_start=start,
        codepoint_end=end,
        utf16_start=utf16_start,
        utf16_end=utf16_end,
    )


def apply_exact_patch(candidate: str, quote: GroundedEvidence, replacement: str) -> str:
    if quote.status != "grounded" or quote.codepoint_start is None or quote.codepoint_end is None:
        raise ValueError("Only a unique, grounded quote can be edited.")
    return candidate[: quote.codepoint_start] + replacement + candidate[quote.codepoint_end :]


def check_utility(
    *,
    previous: str,
    proposed: str,
    original_sanitized: str,
    pins: list[str],
    expected_tokens: list[str],
    authorized_quote: GroundedEvidence,
    replacement: str,
) -> UtilityLedger:
    token_ok = Counter(_extract_restore_handles(proposed, expected_tokens)) == Counter(expected_tokens)
    pins_ok = all(pin in proposed for pin in pins)
    expected = apply_exact_patch(previous, authorized_quote, replacement)
    span_ok = proposed == expected
    per_pass = Levenshtein.normalized_distance(previous, proposed)
    cumulative = Levenshtein.normalized_distance(original_sanitized, proposed)
    reasons: list[str] = []
    heuristic_warnings = _patch_boundary_warnings(previous, authorized_quote, replacement)
    if not token_ok:
        reasons.append("Restorable surrogate multiset changed.")
    if not pins_ok:
        reasons.append("A confirmed utility pin was lost.")
    if not span_ok:
        reasons.append("The patch changed text outside the authorized clue span.")
    if per_pass > MAX_PER_PASS_EDIT_RATIO:
        reasons.append("The pass changed more than 20% of the candidate.")
    if cumulative > MAX_CUMULATIVE_EDIT_RATIO:
        reasons.append("Cumulative edits exceed the 40% utility budget.")
    reasons.extend(heuristic_warnings)
    return UtilityLedger(
        accepted=not reasons,
        reasons=reasons or ["Surrogates, pins, edit scope, and utility budget are intact."],
        tokens_intact=token_ok,
        pins_intact=pins_ok,
        authorized_span_only=span_ok,
        per_pass_edit_ratio=per_pass,
        cumulative_edit_ratio=cumulative,
        heuristic_warnings=heuristic_warnings,
    )


def _extract_restore_handles(text: str, handles: list[str]) -> list[str]:
    ordered = sorted({handle for handle in handles if handle}, key=lambda value: (-len(value), value))
    if not ordered:
        return []
    pattern = re.compile("|".join(re.escape(handle) for handle in ordered))
    return [match.group(0) for match in pattern.finditer(text)]


def repair_sentence_replacement(evidence_quote: str, replacement: str) -> str:
    evidence = evidence_quote.strip()
    repaired = replacement.strip()
    if not evidence.endswith((".", "!", "?")) or not repaired:
        return repaired
    words = re.findall(r"[\w'-]+", repaired)
    first_word = words[0].casefold() if words else ""
    if first_word in SUBJECT_PRONOUNS:
        repaired = re.sub(r"^[A-Za-z]+", "The subject", repaired, count=1)
    elif not _has_apparent_sentence_subject(repaired):
        repaired = f"The subject {repaired[0].lower()}{repaired[1:]}"
    first_alpha = next((index for index, character in enumerate(repaired) if character.isalpha()), None)
    if first_alpha is not None:
        repaired = f"{repaired[:first_alpha]}{repaired[first_alpha].upper()}{repaired[first_alpha + 1 :]}"
    if not repaired.endswith((".", "!", "?")):
        repaired = f"{repaired}{evidence[-1]}"
    return repaired


def _has_apparent_sentence_subject(replacement: str) -> bool:
    if TOKEN_PATTERN.match(replacement):
        return True
    words = re.findall(r"[\w'-]+", replacement)
    if not words:
        return False
    first = words[0].casefold()
    if first in DETERMINERS or first in SUBJECT_PRONOUNS or first == "subject":
        return True
    return first not in VERBISH_SENTENCE_STARTS and not first.endswith(("ed", "ing"))


def _patch_boundary_warnings(
    previous: str,
    authorized_quote: GroundedEvidence,
    replacement: str,
) -> list[str]:
    if authorized_quote.codepoint_start is None or authorized_quote.codepoint_end is None:
        return []
    left_words = re.findall(r"[\w'-]+", previous[: authorized_quote.codepoint_start].casefold())
    replacement_words = re.findall(r"[\w'-]+", replacement.casefold())
    right_words = re.findall(r"[\w'-]+", previous[authorized_quote.codepoint_end :].casefold())
    left_collision = bool(
        left_words and replacement_words and left_words[-1] in DETERMINERS and replacement_words[0] in DETERMINERS
    )
    right_collision = bool(
        replacement_words and right_words and replacement_words[-1] in DETERMINERS and right_words[0] in DETERMINERS
    )
    warnings: list[str] = []
    if left_collision or right_collision:
        warnings.append("Patch creates adjacent determiners at the edit boundary.")

    original_span = previous[authorized_quote.codepoint_start : authorized_quote.codepoint_end].strip()
    replacement_span = replacement.strip()
    if original_span.endswith((".", "!", "?")):
        if not replacement_span.endswith((".", "!", "?")):
            warnings.append("Patch removes sentence-boundary punctuation.")
        original_first = next((character for character in original_span if character.isalpha()), "")
        replacement_first = next((character for character in replacement_span if character.isalpha()), "")
        if original_first.isupper() and replacement_first and not replacement_first.isupper():
            warnings.append("Patch breaks sentence-initial capitalization.")
        if not _has_apparent_sentence_subject(replacement_span):
            warnings.append("Patch appears to remove the sentence subject.")
    return warnings
