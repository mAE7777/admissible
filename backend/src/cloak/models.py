from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionCreateRequest(StrictModel):
    text: str


class ProtectedSubject(StrictModel):
    canonical_identity: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("canonical_identity", "aliases")
    @classmethod
    def reject_empty_values(cls, value: str | list[str]) -> str | list[str]:
        if isinstance(value, str):
            if not value.strip():
                raise ValueError("identity cannot be blank")
            return value.strip()
        clean = [item.strip() for item in value if item.strip()]
        if len(clean) != len(set(clean)):
            raise ValueError("aliases must be unique")
        return clean


class IdentifierCandidate(StrictModel):
    candidate_id: str
    label: str
    value: str
    occurrence_count: int = Field(ge=1)
    confirmed: bool = False


class UtilityPin(StrictModel):
    value: str
    confirmed: bool = False


class SessionCreateResponse(StrictModel):
    session_id: str
    normalized_text: str
    char_count: int
    subject_suggestions: list[str]
    identifier_candidates: list[IdentifierCandidate]


class ConfirmSessionRequest(StrictModel):
    subject: ProtectedSubject
    identifiers: list[str] = Field(default_factory=list, max_length=100)
    pins: list[str] = Field(default_factory=list, max_length=30)
    task: str = Field(min_length=1, max_length=2000)

    @field_validator("task")
    @classmethod
    def normalize_task(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("task cannot be blank")
        return clean


class SanitizedCandidate(StrictModel):
    text: str
    sha256: str
    parent_sha256: str | None = None
    pass_number: int = Field(ge=0)
    per_pass_edit_ratio: float = Field(ge=0, le=1)
    cumulative_edit_ratio: float = Field(ge=0, le=1)
    token_ids: list[str]


class ConfirmSessionResponse(StrictModel):
    session_id: str
    candidate: SanitizedCandidate
    confirmed_identifiers: int
    confirmed_pins: int


class SanitizedEnvelope(StrictModel):
    """The only value accepted at the remote attacker boundary."""

    candidate_text: str
    candidate_sha256: str
    phase: Literal["discovery", "post_edit", "holdout", "counterfactual", "control"]


class IdentityHypothesis(StrictModel):
    identity: str = Field(min_length=1, max_length=300)
    confidence: float = Field(ge=0, le=1)
    evidence_quotes: list[str] = Field(default_factory=list, max_length=5)


class AttackResult(StrictModel):
    requested_model: str = "gpt-5.6"
    returned_model: str
    hypotheses: list[IdentityHypothesis] = Field(default_factory=list, max_length=5)
    refusal: str | None = None
    error: str | None = None
    latency_ms: int = Field(ge=0)
    usage: dict[str, int] = Field(default_factory=dict)


class GroundedEvidence(StrictModel):
    quote: str
    status: Literal["grounded", "missing", "ambiguous"]
    codepoint_start: int | None = None
    codepoint_end: int | None = None
    utf16_start: int | None = None
    utf16_end: int | None = None


class PatchProposal(StrictModel):
    old_text: str = Field(min_length=1, max_length=2000)
    replacement: str = Field(min_length=1, max_length=2000)
    rationale: str = Field(min_length=1, max_length=300)
    tokenize_values: list[str] = Field(default_factory=list, max_length=10)


class UtilityLedger(StrictModel):
    accepted: bool
    reasons: list[str]
    tokens_intact: bool
    pins_intact: bool
    authorized_span_only: bool
    per_pass_edit_ratio: float = Field(ge=0, le=1)
    cumulative_edit_ratio: float = Field(ge=0, le=1)
    heuristic_warnings: list[str] = Field(default_factory=list)


class TraceEvent(StrictModel):
    event_id: str
    mode: Literal["live", "recorded"]
    phase: str
    title: str
    detail: str
    status: Literal["active", "passed", "blocked", "changed", "info"]
    prompt_version: str = "cloak-attacker-2026-07-16.v2"
    schema_version: str = "cloak-trace-2026-07-15.v1"
    model_version: str = "gpt-5.6"
    candidate: SanitizedCandidate | None = None
    attack: AttackResult | None = None
    evidence: list[GroundedEvidence] = Field(default_factory=list)
    patch: PatchProposal | None = None
    utility: UtilityLedger | None = None
    conflicting_facts: list[str] = Field(default_factory=list, max_length=10)
    calls_used: int = Field(default=0, ge=0, le=8)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RunResponse(StrictModel):
    run_id: str
    outcome: Literal["passed", "blocked"]
    reason: str
    candidate: SanitizedCandidate
    calls_used: int = Field(ge=0, le=8)


class RestoreRequest(StrictModel):
    text: str = Field(max_length=100_000)


class RestoreResult(StrictModel):
    restored_text: str
    restored_count: int = Field(ge=0)
    missing_tokens: list[str]
    duplicated_tokens: list[str]
    mutated_tokens: list[str]
    unknown_tokens: list[str]


class HealthResponse(StrictModel):
    status: Literal["ready", "degraded"]
    ollama_ready: bool
    ollama_model: str
    attacker_ready: bool
    attacker_model: Literal["gpt-5.6"] = "gpt-5.6"
    privacy_boundary: str = "loopback-only"


class CausalRequest(StrictModel):
    quote: str


class CausalResult(StrictModel):
    verdict: Literal["causal", "not_causal", "inconclusive"]
    detail: str
    calls_used: int = Field(ge=0, le=2)
    counterfactual: AttackResult | None = None
    control: AttackResult | None = None


class BenchmarkAttackRequest(StrictModel):
    pass


class BenchmarkAttackResponse(StrictModel):
    case_id: str
    condition: Literal["raw", "direct_identifier_only"]
    candidate_sha256: str
    detected_direct_identifiers: int = Field(ge=0)
    detected_entity_types: list[str] = Field(default_factory=list)
    attack: AttackResult
