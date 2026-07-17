from __future__ import annotations

import base64
import json
import re
import secrets
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from presidio_analyzer import Pattern, PatternRecognizer
from pydantic import Field

from cloak.models import ProtectedSubject, StrictModel
from cloak.privacy import TOKEN_PATTERN, sha256_text
from cloak.services.attacker import ATTACKER_MODEL, model_is_gpt_56

Difficulty = Literal["direct_pii", "single_distinctive_clue", "aggregate_quasi_identifiers"]
BenchmarkCondition = Literal["raw", "direct_identifier_only"]

DIFFICULTIES: tuple[Difficulty, ...] = (
    "direct_pii",
    "single_distinctive_clue",
    "aggregate_quasi_identifiers",
)
DEFAULT_CASES_PATH = Path(__file__).resolve().parents[3] / "qa-reports" / "benchmark-smoke-cases.json"


class BenchmarkCase(StrictModel):
    case_id: str = Field(pattern=r"^[a-z0-9-]+$")
    difficulty: Difficulty
    protected_subject: ProtectedSubject
    direct_identifiers: list[str] = Field(min_length=1)
    utility_pins: list[str] = Field(default_factory=list)
    identifying_clues: list[str] = Field(min_length=1)
    identity_is_substance: bool
    substance_note: str | None
    document: str = Field(min_length=100, max_length=12_000)


class BenchmarkCorpus(StrictModel):
    schema_version: str
    provenance: str
    language: Literal["en"]
    cases: list[BenchmarkCase] = Field(min_length=15, max_length=20)


class NaiveCandidate(StrictModel):
    text: str
    sha256: str
    detected_values: list[str]
    detected_entity_types: list[str]
    token_count: int = Field(ge=0)


DIRECT_RECOGNIZERS = (
    PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        patterns=[Pattern("email", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", 0.85)],
    ),
    PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[
            Pattern(
                "north_american_phone",
                r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)",
                0.8,
            )
        ],
    ),
    PatternRecognizer(
        supported_entity="US_SSN",
        patterns=[Pattern("us_ssn", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", 0.8)],
    ),
    PatternRecognizer(
        supported_entity="IP_ADDRESS",
        patterns=[Pattern("ipv4", r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", 0.7)],
    ),
)


def load_benchmark_corpus(path: Path = DEFAULT_CASES_PATH) -> BenchmarkCorpus:
    corpus = BenchmarkCorpus.model_validate_json(path.read_text(encoding="utf-8"))
    case_ids = [case.case_id for case in corpus.cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Benchmark case IDs must be unique.")
    counts = Counter(case.difficulty for case in corpus.cases)
    if any(counts[difficulty] < 5 for difficulty in DIFFICULTIES):
        raise ValueError("The smoke set must contain at least five cases from each difficulty family.")
    for case in corpus.cases:
        if case.protected_subject.canonical_identity not in case.document:
            raise ValueError(f"{case.case_id}: canonical identity must occur in the raw fixture.")
        if any(value not in case.document for value in case.direct_identifiers):
            raise ValueError(f"{case.case_id}: every declared direct identifier must occur in the fixture.")
        if any(pin not in case.document for pin in case.utility_pins):
            raise ValueError(f"{case.case_id}: every utility pin must occur in the fixture.")
        if any(clue not in case.document for clue in case.identifying_clues):
            raise ValueError(f"{case.case_id}: every identifying clue must occur in the fixture.")
    return corpus


def case_by_id(case_id: str, path: Path = DEFAULT_CASES_PATH) -> BenchmarkCase:
    for case in load_benchmark_corpus(path).cases:
        if case.case_id == case_id:
            return case
    raise KeyError(case_id)


def presidio_direct_identifiers(text: str) -> tuple[list[str], list[str]]:
    spans: list[tuple[int, int, str]] = []
    for recognizer in DIRECT_RECOGNIZERS:
        results = recognizer.analyze(text=text, entities=recognizer.supported_entities)
        spans.extend((result.start, result.end, result.entity_type) for result in results)
    values: list[str] = []
    entity_types: list[str] = []
    for start, end, entity_type in sorted(spans):
        value = text[start:end]
        if value not in values:
            values.append(value)
            entity_types.append(entity_type)
    return values, entity_types


def naive_direct_identifier_candidate(case: BenchmarkCase) -> NaiveCandidate:
    detected_values, entity_types = presidio_direct_identifiers(case.document)
    aliases = [case.protected_subject.canonical_identity, *case.protected_subject.aliases]
    values = sorted({*aliases, *detected_values}, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(value) for value in values), re.IGNORECASE)
    surface_tokens: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        surface = match.group(0)
        token = surface_tokens.get(surface.casefold())
        if token is None:
            random_part = base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")
            token = f"[[CX_{random_part}_{secrets.token_hex(4)}]]"
            surface_tokens[surface.casefold()] = token
        return token

    text = pattern.sub(replace, case.document)
    return NaiveCandidate(
        text=text,
        sha256=sha256_text(text),
        detected_values=detected_values,
        detected_entity_types=sorted(set(entity_types)),
        token_count=len(TOKEN_PATTERN.findall(text)),
    )


def benchmark_candidate(case: BenchmarkCase, condition: BenchmarkCondition) -> NaiveCandidate:
    if condition == "direct_identifier_only":
        return naive_direct_identifier_candidate(case)
    return NaiveCandidate(
        text=case.document,
        sha256=sha256_text(case.document),
        detected_values=[],
        detected_entity_types=[],
        token_count=len(TOKEN_PATTERN.findall(case.document)),
    )


def corpus_fingerprint(case: BenchmarkCase) -> str:
    canonical = json.dumps(
        case.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_text(canonical)


def validate_result_cache_models(payload: dict[str, Any]) -> None:
    if payload.get("attacker") != ATTACKER_MODEL:
        raise ValueError("Benchmark result cache requested a model other than GPT-5.6.")
    cases = payload.get("cases")
    if not isinstance(cases, dict):
        raise ValueError("Benchmark result cache has no case mapping.")
    for case_id, case_payload in cases.items():
        if not isinstance(case_payload, dict):
            raise ValueError(f"{case_id}: invalid cached case payload.")
        conditions = case_payload.get("conditions", {})
        if not isinstance(conditions, dict):
            raise ValueError(f"{case_id}: invalid cached condition mapping.")
        for condition, outcome in conditions.items():
            if not isinstance(outcome, dict) or outcome.get("status") != "ok":
                continue
            returned_models = outcome.get("returned_models")
            if (
                not isinstance(returned_models, list)
                or not returned_models
                or any(not isinstance(model, str) or not model_is_gpt_56(model) for model in returned_models)
            ):
                raise ValueError(f"{case_id}/{condition}: cached result contains a non-GPT-5.6 model.")
