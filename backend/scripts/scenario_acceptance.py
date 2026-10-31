from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from openai import AsyncOpenAI
from openai.types.shared_params import Reasoning
from pydantic import Field

from admissible.controller import CONTROLLER_PROTOCOL_VERSION, MAX_CALLS, Controller, parse_sse_payload
from admissible.models import (
    AttackResult,
    ConfirmSessionRequest,
    ProtectedSubject,
    SanitizedEnvelope,
    StrictModel,
)
from admissible.privacy import identity_rank, sha256_text
from admissible.services.attacker import ATTACKER_MODEL, AttackerOutput, model_is_gpt_56
from admissible.services.ollama import OllamaAnonymizer
from admissible.sessions import SessionStore

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES = REPO_ROOT / "evaluation" / "scenario-acceptance-cases.json"
DEFAULT_RESULTS = REPO_ROOT / "evaluation" / "scenario-acceptance-results.json"
DEFAULT_REPORT = REPO_ROOT / "evaluation" / "scenario-acceptance-report.md"
COMMITTED_CORPUS_SHA256 = "af3c5525734287424473a7621baf22805f2215af14c5cf66efdccadcc654420e"
PROTOCOL_VERSION = "cloak-scenario-acceptance-2026-07-16.v2"
TASK_PROMPT_VERSION = "cloak-scenario-task-2026-07-16.v4"
SANITY_SCENARIO_ID = "contract-employment-raleigh"
LINKAGE_PROTOCOL_VERSION = "cloak-scenario-linkage-2026-07-16.v1"
AUXILIARY_POOL_SIZE = 64


def local_api_key() -> str | None:
    configured = os.getenv("OPENAI_API_KEY")
    if configured:
        return configured
    path = REPO_ROOT / ".env.local"
    if not path.exists():
        return None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        if key.strip() == "OPENAI_API_KEY":
            clean = value.strip().strip('"\'')
            return clean or None
    return None


class RosterEntry(StrictModel):
    identity: str
    profile: str


class AcceptanceCase(StrictModel):
    scenario_id: str
    category: Literal[
        "contract",
        "medical_record",
        "immigration_narrative",
        "financial_statement",
        "hr_workplace_complaint",
    ]
    language: Literal["en"]
    source_kind: str
    source_title: str
    source_url: str | None = None
    private_persona: bool
    protected_subject: ProtectedSubject
    direct_identifiers: list[str]
    utility_pins: list[str]
    task: str
    expected_findings: list[str]
    identity_is_substance: bool
    boundary_note: str
    auxiliary_roster: list[RosterEntry]
    document: str


class AcceptanceCorpus(StrictModel):
    schema_version: str
    language_scope: list[str]
    provenance: str
    threat_model: str
    scenarios: list[AcceptanceCase]


class TaskOutput(StrictModel):
    answer: str = Field(min_length=1)


class UtilityJudgment(StrictModel):
    risk_issue_coverage: int = Field(ge=0, le=40)
    advice_fidelity: int = Field(ge=0, le=30)
    actionability: int = Field(ge=0, le=20)
    factual_consistency: int = Field(ge=0, le=10)
    same_practical_value: bool
    critical_omissions: list[str] = Field(default_factory=list, max_length=10)
    substantive_distortions: list[str] = Field(default_factory=list, max_length=10)
    rationale: str = Field(min_length=1, max_length=1500)


class RemoteBudget:
    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("Remote-call ceiling cannot be negative.")
        self.limit = limit
        self.used = 0

    def reserve_scenario(self) -> None:
        maximum = 20  # two eight-call controller tiers, one web-linkage attack, and three task/utility calls
        if self.used + maximum > self.limit:
            raise RuntimeError(
                f"Remote-call ceiling would be exceeded: {self.used} used, {maximum} reserved, {self.limit} allowed."
            )

    def consume(self) -> None:
        if self.used >= self.limit:
            raise RuntimeError(f"Remote-call ceiling exhausted at {self.limit} calls.")
        self.used += 1


def score_utility_judgment(judgment: UtilityJudgment, metadata: dict[str, Any]) -> dict[str, Any]:
    score = (
        judgment.risk_issue_coverage
        + judgment.advice_fidelity
        + judgment.actionability
        + judgment.factual_consistency
    )
    equivalent = (
        score >= 85
        and judgment.same_practical_value
        and not judgment.critical_omissions
        and not judgment.substantive_distortions
    )
    label = "equivalent" if equivalent else "partial" if score >= 65 else "degraded"
    return {
        **judgment.model_dump(mode="json"),
        "score": score,
        "label": label,
        "equivalent": equivalent,
        **metadata,
    }


def _usage(response: Any) -> dict[str, int]:
    usage = response.usage
    if usage is None:
        return {}
    return {
        "input_tokens": int(usage.input_tokens),
        "output_tokens": int(usage.output_tokens),
        "total_tokens": int(usage.total_tokens),
    }


class AcceptanceRemote:
    """Evaluation-only GPT-5.6 client for committed public/synthetic scenario fixtures."""

    def __init__(self, budget: RemoteBudget, api_key: str | None = None) -> None:
        key = api_key or local_api_key()
        if not key:
            raise RuntimeError("Set OPENAI_API_KEY or place it in ignored .env.local before live scenario acceptance.")
        self.budget = budget
        self.client = AsyncOpenAI(api_key=key, timeout=120.0)

    async def close(self) -> None:
        await self.client.close()

    async def parse(
        self,
        *,
        instructions: str,
        input_text: str,
        text_format: type[StrictModel],
        effort: Literal["medium", "high"] = "medium",
        request_timeout: float = 120.0,
        web_search: bool = False,
    ) -> tuple[StrictModel, dict[str, Any]]:
        self.budget.consume()
        started = time.monotonic()
        if web_search:
            response = await self.client.responses.parse(
                model=ATTACKER_MODEL,
                instructions=instructions,
                input=input_text,
                reasoning=Reasoning(effort=effort),
                text_format=text_format,
                tools=[{"type": "web_search", "search_context_size": "low"}],
                tool_choice="required",
                max_tool_calls=3,
                store=False,
                timeout=request_timeout,
            )
        else:
            response = await self.client.responses.parse(
                model=ATTACKER_MODEL,
                instructions=instructions,
                input=input_text,
                reasoning=Reasoning(effort=effort),
                text_format=text_format,
                store=False,
                timeout=request_timeout,
            )
        latency_ms = int((time.monotonic() - started) * 1000)
        if not model_is_gpt_56(response.model):
            raise RuntimeError(f"Blocked unexpected evaluation model: {response.model}")
        if response.output_parsed is None:
            raise RuntimeError("GPT-5.6 returned no structured evaluation output.")
        metadata = {
            "returned_model": response.model,
            "latency_ms": latency_ms,
            "usage": _usage(response),
            "web_search_calls": sum(item.type == "web_search_call" for item in response.output),
        }
        return cast(StrictModel, response.output_parsed), metadata

    async def run_task(
        self,
        case: AcceptanceCase,
        document: str,
        restore_handles: list[str] | None = None,
    ) -> dict[str, Any]:
        handles = list(dict.fromkeys(restore_handles or []))
        instructions = (
            f"Protocol {TASK_PROMPT_VERSION}. Complete the user's real document task using only the supplied document. "
            "Be concrete, prioritize substantive issues, and do not invent missing facts. Answer in the same language "
            "as the task. Natural-looking values listed as privacy-safe surrogates are fictional replacements, not "
            "the original identity. Preserve each surrogate byte-for-byte whenever you use it; do not identify the "
            "original. At the end, add a short 'Preserved references' line containing every supplied surrogate "
            "exactly once. Omit that line when no surrogate list is supplied."
        )
        surrogate_context = (
            "\n\nPRIVACY-SAFE SURROGATES:\n" + "\n".join(f"- {item}" for item in handles)
            if handles
            else ""
        )
        parsed, metadata = await self.parse(
            instructions=instructions,
            input_text=f"TASK:\n{case.task}\n\nDOCUMENT:\n{document}{surrogate_context}",
            text_format=TaskOutput,
        )
        task_output = cast(TaskOutput, parsed)
        return {"answer": task_output.answer, **metadata}

    async def judge_utility(
        self,
        case: AcceptanceCase,
        raw_answer: str,
        restored_sanitized_answer: str,
    ) -> dict[str, Any]:
        instructions = (
            f"Protocol {PROTOCOL_VERSION}. You are a strict document-task utility judge. Compare two answers to the "
            "same task against the supplied source document. Treat the source document as factual ground truth and "
            "the raw-document answer as the utility reference, but penalize either answer for invented facts or a "
            "missed required finding. Score substantive value, not wording or style. Do not grant privacy-related "
            "leniency. A real "
            "user "
            "has the same practical value only if the sanitized answer catches the same material risks, preserves the "
            "same factual qualifications, and gives comparably actionable advice. List every critical omission or "
            "distortion. Scores: issue/risk coverage 0-40, advice fidelity 0-30, actionability 0-20, factual "
            "consistency "
            "0-10."
        )
        judge_input = (
            f"TASK:\n{case.task}\n\nSOURCE DOCUMENT:\n{case.document}"
            "\n\nREQUIRED FINDINGS FOR STRICT COVERAGE:\n"
            + "\n".join(f"- {item}" for item in case.expected_findings)
            + f"\n\nRAW-DOCUMENT ANSWER:\n{raw_answer}"
            + f"\n\nRESTORED SANITIZED-DOCUMENT ANSWER:\n{restored_sanitized_answer}"
        )
        parsed, metadata = await self.parse(
            instructions=instructions,
            input_text=judge_input,
            text_format=UtilityJudgment,
            effort="high",
        )
        judgment = cast(UtilityJudgment, parsed)
        return score_utility_judgment(judgment, metadata)


class GeneralPopulationAttacker:
    """Primary deployed threat: GPT-5.6 sees only the sanitized candidate and no auxiliary roster."""

    def __init__(self, remote: AcceptanceRemote) -> None:
        self.remote = remote
        self.calls = 0

    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult:
        instructions = (
            f"Protocol {PROTOCOL_VERSION}. You are a re-identification evaluator. Given only the sanitized "
            "document and your general model knowledge, return up to five ranked guesses for the single real person "
            "the document is about. You have no auxiliary roster. For each guess, include a probability and up to "
            "five exact verbatim quotes from the document. Never invent or paraphrase evidence and never provide "
            "hidden reasoning. An empty list is required when a named identity is not supportable."
        )
        parsed, metadata = await self.remote.parse(
            instructions=instructions,
            input_text=envelope.candidate_text,
            text_format=AttackerOutput,
            effort="high" if envelope.phase == "holdout" else "medium",
            request_timeout=150.0 if envelope.phase == "holdout" else 90.0,
        )
        output = cast(AttackerOutput, parsed)
        self.calls += 1
        return AttackResult(
            returned_model=str(metadata["returned_model"]),
            hypotheses=output.hypotheses,
            latency_ms=int(metadata["latency_ms"]),
            usage=cast(dict[str, int], metadata["usage"]),
        )


class RosterAttacker:
    """Closed-world private-person attacker; the auxiliary roster is synthetic and evaluation-only."""

    def __init__(self, remote: AcceptanceRemote, case: AcceptanceCase) -> None:
        self.remote = remote
        self.case = case
        self.calls = 0

    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult:
        roster = json.dumps([item.model_dump(mode="json") for item in self.case.auxiliary_roster], ensure_ascii=False)
        instructions = (
            f"Protocol {PROTOCOL_VERSION}. You are a closed-world re-identification evaluator for a private-person "
            "scenario. Given a sanitized document and a synthetic auxiliary roster, return up to five ranked identity "
            "guesses drawn only from the roster. For each guess, include a probability and up to five exact verbatim "
            "quotes copied from the sanitized document. Never quote the roster, invent evidence, paraphrase evidence, "
            "or provide hidden reasoning. An empty list is valid when the document does not support a roster match. "
            f"SYNTHETIC AUXILIARY ROSTER:\n{roster}"
        )
        parsed, metadata = await self.remote.parse(
            instructions=instructions,
            input_text=envelope.candidate_text,
            text_format=AttackerOutput,
            effort="high" if envelope.phase == "holdout" else "medium",
            request_timeout=150.0 if envelope.phase == "holdout" else 90.0,
        )
        output = cast(AttackerOutput, parsed)
        self.calls += 1
        return AttackResult(
            returned_model=str(metadata["returned_model"]),
            hypotheses=output.hypotheses,
            latency_ms=int(metadata["latency_ms"]),
            usage=cast(dict[str, int], metadata["usage"]),
        )


LINKAGE_FIRST_NAMES = (
    "Adrian",
    "Amara",
    "Bianca",
    "Calvin",
    "Dalia",
    "Elise",
    "Farah",
    "Gavin",
    "Imani",
    "Jonah",
    "Kira",
    "Luis",
    "Maya",
    "Nolan",
    "Priya",
    "Rafael",
)
LINKAGE_LAST_NAMES = (
    "Archer",
    "Bishop",
    "Chandra",
    "Diaz",
    "Everett",
    "Foster",
    "Gupta",
    "Hawkins",
    "Ibrahim",
    "Jensen",
    "Kim",
    "Lawson",
    "Morales",
    "Nolan",
    "Patel",
    "Reyes",
)


def _synthetic_decoy_profile(case: AcceptanceCase, index: int, rng: random.Random) -> str:
    if case.category == "contract":
        contract_cities = ("Raleigh", "Durham", "Charlotte", "Richmond", "Greensboro")
        contract_roles = ("product-operations manager", "implementation director", "clinical-program lead")
        contract_sectors = ("clinical-software", "hospital-analytics", "healthcare-workflow")
        contract_months = ("August", "September", "October", "January")
        contract_salaries = ("$142,000", "$145,000", "$146,000", "$149,000")
        contract_bonuses = ("$18,000", "$20,000", "$22,000", "no")
        return (
            f"A {rng.choice(contract_cities)} {rng.choice(contract_roles)} joining a "
            f"{rng.choice(contract_sectors)} employer in {rng.choice(contract_months)} 2025 at "
            f"{rng.choice(contract_salaries)} with {rng.choice(contract_bonuses)} signing bonus; "
            f"record {index:02d} notes healthcare client work."
        )
    if case.category == "medical_record":
        medical_ages = (33, 34, 35, 36)
        medical_cities = ("Detroit", "Dearborn", "Toledo", "Ann Arbor")
        medical_jobs = ("Arabic medical interpreter", "hospital interpreter", "social worker", "pharmacist")
        medical_conditions = ("Crohn's disease", "ulcerative colitis", "rheumatoid arthritis")
        medical_medicines = ("adalimumab", "ustekinumab", "vedolizumab")
        medical_screens = ("positive latent-TB screen", "negative TB screen", "previously treated TB")
        medical_plans = ("pregnancy plans", "no current pregnancy plans", "fertility counseling")
        return (
            f"A {rng.choice(medical_ages)}-year-old {rng.choice(medical_cities)}-area "
            f"{rng.choice(medical_jobs)} with {rng.choice(medical_conditions)} on "
            f"{rng.choice(medical_medicines)}, a {rng.choice(medical_screens)}, and "
            f"{rng.choice(medical_plans)}; broker cohort {index:02d}."
        )
    if case.category == "immigration_narrative":
        immigration_towns = ("San Isidro", "El Pinar", "Santa Rosa", "Puerto Verde")
        immigration_roles = (
            "municipal payroll analyst",
            "procurement clerk",
            "municipal accountant",
            "records technician",
        )
        immigration_contracts = ("irrigation", "road", "school-meal", "water-utility")
        immigration_years = (2022, 2023, 2024)
        immigration_events = (
            "received threats",
            "was assaulted",
            "a relative was threatened",
            "lost municipal access",
        )
        return (
            f"A {rng.choice(immigration_roles)} from {rng.choice(immigration_towns)} who reported "
            f"{rng.choice(immigration_contracts)}-contract irregularities in "
            f"{rng.choice(immigration_years)}, {rng.choice(immigration_events)}, and later attempted "
            "internal relocation; "
            f"case-index record {index:02d}."
        )
    if case.category == "financial_statement":
        financial_cities = ("Providence", "Warwick", "Newport", "Cranston")
        financial_jobs = ("nonprofit grants coordinator", "museum administrator", "consultant", "school employee")
        financial_merchants = ("Montreal hotel", "Boston hotel", "ferry terminal", "online pharmacy")
        financial_limits = ("$8,000", "$9,000", "$10,000", "$12,000")
        financial_statuses = ("a recent late payment", "no late payment", "a disputed fee", "a returned payment")
        return (
            f"A {rng.choice(financial_cities)} {rng.choice(financial_jobs)} whose June card activity "
            f"included a {rng.choice(financial_merchants)} on an account near its "
            f"{rng.choice(financial_limits)} limit with {rng.choice(financial_statuses)}; "
            f"consumer-file record {index:02d}."
        )
    hr_cities = ("Chicago", "Milwaukee", "Evanston", "Gary")
    hr_roles = ("route-analytics lead", "dispatch supervisor", "logistics analyst", "warehouse planner")
    hr_leaves = ("parental leave", "medical leave", "military leave", "caregiver leave")
    hr_actions = ("a night schedule", "a weekend schedule", "project removal", "a written warning")
    return (
        f"A {rng.choice(hr_cities)} {rng.choice(hr_roles)} who returned from {rng.choice(hr_leaves)} "
        f"in early 2026, was denied promotion, made an internal complaint, and then received "
        f"{rng.choice(hr_actions)}; "
        f"employment-file record {index:02d}."
    )


def synthetic_auxiliary_population(case: AcceptanceCase) -> list[RosterEntry]:
    """Build a fixed-size, auditable stand-in for broker and employer linkage records."""
    entries = list(case.auxiliary_roster)
    existing = {entry.identity for entry in entries}
    seed = int(hashlib.sha256(case.scenario_id.encode()).hexdigest()[:16], 16)
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic evaluation population, not a secret
    names = [f"{first} {last}" for first in LINKAGE_FIRST_NAMES for last in LINKAGE_LAST_NAMES]
    rng.shuffle(names)
    for identity in names:
        if identity in existing:
            continue
        entries.append(
            RosterEntry(
                identity=identity,
                profile=_synthetic_decoy_profile(case, len(entries), rng),
            )
        )
        if len(entries) == AUXILIARY_POOL_SIZE:
            break
    if len(entries) != AUXILIARY_POOL_SIZE:
        raise RuntimeError("Could not construct the fixed auxiliary-linkage population.")
    return entries


class WebAuxiliaryLinkageAttacker:
    """Evaluation-only attacker with web search and a 64-person synthetic linkage population."""

    def __init__(self, remote: AcceptanceRemote, case: AcceptanceCase) -> None:
        self.remote = remote
        self.case = case
        self.calls = 0
        self.web_search_calls = 0

    async def attack(self, candidate_text: str, candidate_sha256: str) -> AttackResult:
        population = synthetic_auxiliary_population(self.case)
        roster = json.dumps([item.model_dump(mode="json") for item in population], ensure_ascii=False)
        instructions = (
            f"Protocol {LINKAGE_PROTOCOL_VERSION}. Conduct a direct-intent re-identification stress test. You see "
            "only a sanitized document plus a synthetic 64-person stand-in for data-broker, employer, merchant, "
            "or case-record attributes. Use web search to cross-reference public places, organizations, events, and "
            "other surviving clues when useful. Natural-looking names, organizations, contacts, addresses, and IDs "
            "inside the document may be locally generated surrogates and must not be matched literally. Return up to "
            "five ranked identities drawn only from the supplied population. Include probabilities and up to five "
            "exact verbatim quotes from the sanitized document, never from the auxiliary profiles. Do not invent or "
            "paraphrase evidence and do not expose hidden reasoning. An empty list is valid when linkage is not "
            f"supportable.\n\nSYNTHETIC AUXILIARY POPULATION:\n{roster}"
        )
        parsed, metadata = await self.remote.parse(
            instructions=instructions,
            input_text=candidate_text,
            text_format=AttackerOutput,
            effort="high",
            request_timeout=180.0,
            web_search=True,
        )
        output = cast(AttackerOutput, parsed)
        self.calls += 1
        self.web_search_calls += int(metadata["web_search_calls"])
        return AttackResult(
            returned_model=str(metadata["returned_model"]),
            hypotheses=output.hypotheses,
            latency_ms=int(metadata["latency_ms"]),
            usage=cast(dict[str, int], metadata["usage"]),
        )


def load_corpus() -> AcceptanceCorpus:
    corpus_bytes = DEFAULT_CASES.read_bytes()
    if hashlib.sha256(corpus_bytes).hexdigest() != COMMITTED_CORPUS_SHA256:
        raise ValueError("Scenario acceptance is restricted to the committed synthetic corpus.")
    corpus = AcceptanceCorpus.model_validate_json(corpus_bytes)
    if corpus.schema_version != PROTOCOL_VERSION:
        raise ValueError("Unsupported scenario-acceptance corpus schema.")
    if len(corpus.scenarios) != 5:
        raise ValueError("English acceptance corpus must contain exactly five scenarios.")
    if {case.category for case in corpus.scenarios} != {
        "contract",
        "medical_record",
        "immigration_narrative",
        "financial_statement",
        "hr_workplace_complaint",
    }:
        raise ValueError("Acceptance corpus must cover all five English scenario families.")
    if not all(case.private_persona for case in corpus.scenarios):
        raise ValueError("Every acceptance subject must be a private synthetic persona.")
    if any(case.language != "en" for case in corpus.scenarios):
        raise ValueError("Admissible acceptance is English-only.")
    for case in corpus.scenarios:
        direct_values = [case.protected_subject.canonical_identity, *case.direct_identifiers]
        if any(value not in case.document for value in direct_values):
            raise ValueError(f"{case.scenario_id}: every confirmed direct value must occur in the document.")
        if any(pin not in case.document for pin in case.utility_pins):
            raise ValueError(f"{case.scenario_id}: every utility pin must occur in the document.")
        roster_names = [entry.identity for entry in case.auxiliary_roster]
        if len(roster_names) != 4 or len(roster_names) != len(set(roster_names)):
            raise ValueError(f"{case.scenario_id}: roster must contain four unique private personas.")
        if case.protected_subject.canonical_identity not in roster_names:
            raise ValueError(f"{case.scenario_id}: protected subject must occur in the auxiliary roster.")
    return corpus


def case_fingerprint(case: AcceptanceCase) -> str:
    payload = case.model_dump_json(exclude_none=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_results(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": PROTOCOL_VERSION,
            "attacker": ATTACKER_MODEL,
            "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
            "execution_remote_calls": 0,
            "scenarios": {},
        }
    payload = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    if payload.get("schema_version") != PROTOCOL_VERSION:
        raise ValueError("Unsupported scenario-acceptance result cache.")
    return payload


def archive_superseded_result(results: dict[str, Any], scenario_id: str, result: dict[str, Any]) -> None:
    history = results.setdefault("attempt_history", [])
    if not isinstance(history, list):
        raise ValueError("Scenario-acceptance attempt history is malformed.")
    history.append(
        {
            "scenario_id": scenario_id,
            "archived_at": datetime.now(UTC).isoformat(),
            "reason": "controller, prompt, fixture, or model contract changed",
            "result": result,
        }
    )
    del history[:-50]


def record_failed_attempt(
    results: dict[str, Any],
    *,
    scenario_id: str,
    calls: int,
    error_type: str,
) -> None:
    failures = results.setdefault("failed_attempts", [])
    if not isinstance(failures, list):
        raise ValueError("Scenario-acceptance failed-attempt history is malformed.")
    failures.append(
        {
            "scenario_id": scenario_id,
            "failed_at": datetime.now(UTC).isoformat(),
            "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
            "remote_calls": calls,
            "error_type": error_type,
        }
    )
    del failures[:-50]


def cache_is_current(result: object, case: AcceptanceCase) -> bool:
    return (
        isinstance(result, dict)
        and result.get("status") == "ok"
        and result.get("case_fingerprint") == case_fingerprint(case)
        and result.get("controller_protocol_version") == CONTROLLER_PROTOCOL_VERSION
        and result.get("task_prompt_version") == TASK_PROMPT_VERSION
        and result.get("linkage_protocol_version") == LINKAGE_PROTOCOL_VERSION
        and result_models_are_gpt_56(result)
        and result_evidence_is_consistent(result, case)
    )


def result_models_are_gpt_56(result: dict[str, Any]) -> bool:
    try:
        privacy_models = [
            *result["privacy"]["auxiliary_free"]["returned_models"],
            *result["privacy"]["realistic"]["returned_models"],
            *result["privacy"]["closed_world"]["returned_models"],
        ]
        task_models = [
            result["raw_task_answer"]["returned_model"],
            result["sanitized_task_answer"]["returned_model"],
            result["utility"]["returned_model"],
        ]
    except (KeyError, TypeError):
        return False
    models = [*privacy_models, *task_models]
    return bool(models) and all(isinstance(model, str) and model_is_gpt_56(model) for model in models)


def _privacy_result_is_consistent(payload: object, *, linkage: bool) -> bool:
    if not isinstance(payload, dict):
        return False
    reidentified = payload.get("reidentified")
    verified = payload.get("verified")
    rank = payload.get("rank")
    calls = payload.get("calls")
    if not isinstance(reidentified, bool) or not isinstance(verified, bool):
        return False
    if reidentified != (isinstance(rank, int) and not isinstance(rank, bool) and 1 <= rank <= 5):
        return False
    if not isinstance(calls, int) or isinstance(calls, bool) or calls < 1:
        return False
    if linkage:
        web_search_calls = payload.get("web_search_calls")
        return (
            calls == 1
            and isinstance(web_search_calls, int)
            and not isinstance(web_search_calls, bool)
            and web_search_calls >= 1
            and payload.get("auxiliary_population_size") == AUXILIARY_POOL_SIZE
            and payload.get("edits") == 0
            and verified == (not reidentified)
            and payload.get("final_phase") == ("linkage_blocked" if reidentified else "linkage_passed")
            and payload.get("threat_model")
            == "web search plus synthetic broker/employer/merchant/case-record linkage population"
        )
    return (
        calls <= MAX_CALLS
        and verified == (payload.get("final_phase") == "run_passed")
        and (not verified or not reidentified)
        and payload.get("final_phase") in {"run_passed", "run_blocked"}
    )


def result_evidence_is_consistent(result: dict[str, Any], case: AcceptanceCase) -> bool:
    """Reject stale or internally contradictory cached evaluation claims before zero-call reuse."""
    try:
        privacy = result["privacy"]
        auxiliary_free = privacy["auxiliary_free"]
        linkage = privacy["realistic"]
        closed_world = privacy["closed_world"]
        product_candidate = result["final_sanitized_candidate"]
        closed_candidate = result["closed_world_final_candidate"]
        product_text = product_candidate["text"]
        product_hash = product_candidate["sha256"]
        closed_text = closed_candidate["text"]
        closed_hash = closed_candidate["sha256"]
        total_calls = int(auxiliary_free["calls"]) + int(linkage["calls"]) + int(closed_world["calls"]) + 3
    except (KeyError, TypeError, ValueError):
        return False
    remote_calls = result.get("remote_calls")
    return (
        result.get("category") == case.category
        and result.get("language") == "en"
        and result.get("private_persona") is True
        and _privacy_result_is_consistent(auxiliary_free, linkage=False)
        and _privacy_result_is_consistent(linkage, linkage=True)
        and _privacy_result_is_consistent(closed_world, linkage=False)
        and auxiliary_free.get("candidate_sha256") == product_hash
        and linkage.get("candidate_sha256") == product_hash
        and closed_world.get("candidate_sha256") == closed_hash
        and isinstance(product_text, str)
        and isinstance(product_hash, str)
        and product_hash == sha256_text(product_text)
        and isinstance(closed_text, str)
        and isinstance(closed_hash, str)
        and closed_hash == sha256_text(closed_text)
        and isinstance(remote_calls, int)
        and not isinstance(remote_calls, bool)
        and remote_calls == total_calls
    )


def event_attack(event: dict[str, Any]) -> AttackResult | None:
    payload = event.get("attack")
    return AttackResult.model_validate(payload) if isinstance(payload, dict) else None


def score_privacy(events: list[dict[str, Any]], case: AcceptanceCase) -> dict[str, Any]:
    final = events[-1]
    candidate = final.get("candidate")
    if not isinstance(candidate, dict) or not isinstance(candidate.get("sha256"), str):
        raise RuntimeError("Controller final event omitted a candidate hash.")
    final_hash = candidate["sha256"]
    aliases = [case.protected_subject.canonical_identity, *case.protected_subject.aliases]
    final_attacks: list[AttackResult] = []
    all_attacks: list[AttackResult] = []
    for event in events:
        attack = event_attack(event)
        if attack is None:
            continue
        all_attacks.append(attack)
        event_candidate = event.get("candidate")
        if isinstance(event_candidate, dict) and event_candidate.get("sha256") == final_hash:
            final_attacks.append(attack)
    if not final_attacks:
        raise RuntimeError("No GPT-5.6 attack scored the controller's retained candidate.")
    ranks = [identity_rank([item.identity for item in attack.hypotheses], aliases) for attack in final_attacks]
    recovered = [rank for rank in ranks if rank is not None]
    best_rank = min(recovered) if recovered else None
    evidence: list[str] = []
    if best_rank is not None:
        matching = next(attack for attack, rank in zip(final_attacks, ranks, strict=True) if rank == best_rank)
        evidence = matching.hypotheses[best_rank - 1].evidence_quotes
    return {
        "reidentified": best_rank is not None,
        "rank": best_rank,
        "evidence_quotes": evidence,
        "verified": final.get("phase") == "run_passed",
        "final_phase": final.get("phase"),
        "final_title": final.get("title"),
        "calls": max(int(event.get("calls_used", 0)) for event in events),
        "edits": sum(event.get("phase") == "patch_accepted" for event in events),
        "returned_models": sorted({attack.returned_model for attack in all_attacks}),
        "latency_ms": sum(attack.latency_ms for attack in all_attacks),
        "candidate_sha256": final_hash,
    }


async def score_web_auxiliary_privacy(
    case: AcceptanceCase,
    session: Any,
    remote: AcceptanceRemote,
) -> dict[str, Any]:
    if session.candidate is None:
        raise RuntimeError("Auxiliary-linkage tier received no sanitized candidate.")
    attacker = WebAuxiliaryLinkageAttacker(remote, case)
    attack = await attacker.attack(session.candidate.text, session.candidate.sha256)
    aliases = [case.protected_subject.canonical_identity, *case.protected_subject.aliases]
    rank = identity_rank([item.identity for item in attack.hypotheses], aliases)
    evidence = attack.hypotheses[rank - 1].evidence_quotes if rank is not None else []
    grounded_evidence = [quote for quote in evidence if session.candidate.text.count(quote) == 1]
    return {
        "reidentified": rank is not None,
        "rank": rank,
        "evidence_quotes": evidence,
        "grounded_evidence_quotes": grounded_evidence,
        "verified": rank is None,
        "final_phase": "linkage_passed" if rank is None else "linkage_blocked",
        "final_title": (
            "Not linked by the web-enabled auxiliary attacker"
            if rank is None
            else "Linked by the web-enabled auxiliary attacker"
        ),
        "calls": attacker.calls,
        "web_search_calls": attacker.web_search_calls,
        "edits": 0,
        "returned_models": [attack.returned_model],
        "latency_ms": attack.latency_ms,
        "candidate_sha256": session.candidate.sha256,
        "auxiliary_population_size": AUXILIARY_POOL_SIZE,
        "threat_model": "web search plus synthetic broker/employer/merchant/case-record linkage population",
    }


def confirmed_scenario_session(case: AcceptanceCase) -> Any:
    store = SessionStore()
    created = store.create(case.document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=case.protected_subject,
            identifiers=case.direct_identifiers,
            pins=case.utility_pins,
            task=case.task,
        ),
    )
    session = store.get(created.session_id)
    if session.candidate is None:
        raise RuntimeError("Scenario confirmation did not create a sanitized candidate.")
    leaked = [
        value
        for value in [
            case.protected_subject.canonical_identity,
            *case.protected_subject.aliases,
            *case.direct_identifiers,
        ]
        if value in session.candidate.text
    ]
    if leaked:
        raise RuntimeError(f"Initial sanitized scenario leaked confirmed values: {leaked!r}")
    return session


async def run_controller_tier(case: AcceptanceCase, attacker: Any) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    session = confirmed_scenario_session(case)
    controller = Controller(attacker=attacker, anonymizer=OllamaAnonymizer())
    chunks = [chunk async for chunk in controller.run(session)]
    events = cast(list[dict[str, Any]], parse_sse_payload("".join(chunks)))
    if not events or session.candidate is None:
        raise RuntimeError("Controller returned no scenario trace.")
    return session, events, score_privacy(events, case)


async def run_scenario(case: AcceptanceCase, remote: AcceptanceRemote) -> dict[str, Any]:
    realistic_session, realistic_events, auxiliary_free_privacy = await run_controller_tier(
        case,
        GeneralPopulationAttacker(remote),
    )
    realistic_privacy = await score_web_auxiliary_privacy(case, realistic_session, remote)
    closed_session, closed_events, closed_privacy = await run_controller_tier(case, RosterAttacker(remote, case))

    raw_task = await remote.run_task(case, case.document)
    sanitized_task = await remote.run_task(
        case,
        realistic_session.candidate.text,
        realistic_session.candidate.token_ids,
    )
    sanitized_answer = str(sanitized_task["answer"])
    answer_tokens = realistic_session.vault.handles_in_text(sanitized_answer)
    restored = realistic_session.vault.restore(sanitized_answer)
    unresolved_after_restore = realistic_session.vault.handles_in_text(restored.restored_text)
    restore_exact = (
        bool(answer_tokens)
        and restored.restored_count == len(answer_tokens)
        and not restored.mutated_tokens
        and not restored.unknown_tokens
        and not unresolved_after_restore
    )
    utility = await remote.judge_utility(case, str(raw_task["answer"]), restored.restored_text)
    outcome = {
        "status": "ok",
        "case_fingerprint": case_fingerprint(case),
        "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
        "task_prompt_version": TASK_PROMPT_VERSION,
        "linkage_protocol_version": LINKAGE_PROTOCOL_VERSION,
        "category": case.category,
        "language": case.language,
        "private_persona": case.private_persona,
        "identity_is_substance": case.identity_is_substance,
        "boundary_handling": "pending",
        "privacy": {
            "auxiliary_free": auxiliary_free_privacy,
            "realistic": realistic_privacy,
            "closed_world": closed_privacy,
        },
        "utility": utility,
        "restore": {
            "exact_for_answer_tokens": restore_exact,
            "answer_token_occurrences": len(answer_tokens),
            "restored_count": restored.restored_count,
            "missing_source_tokens": restored.missing_tokens,
            "duplicated_tokens": restored.duplicated_tokens,
            "mutated_tokens": restored.mutated_tokens,
            "unknown_tokens": restored.unknown_tokens,
        },
        "raw_task_answer": raw_task,
        "sanitized_task_answer": sanitized_task,
        "restored_sanitized_answer": restored.restored_text,
        "task_facts": realistic_session.task_facts,
        "closed_world_task_facts": closed_session.task_facts,
        "final_sanitized_candidate": realistic_session.candidate.model_dump(mode="json"),
        "closed_world_final_candidate": closed_session.candidate.model_dump(mode="json"),
        "trace_events": {
            "auxiliary_free": realistic_events,
            "closed_world": closed_events,
        },
        "remote_calls": auxiliary_free_privacy["calls"] + realistic_privacy["calls"] + closed_privacy["calls"] + 3,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    outcome["boundary_handling"] = observed_boundary_handling(outcome)
    return outcome


def _privacy_cell(privacy: dict[str, Any]) -> str:
    if privacy["reidentified"]:
        return f"re-id rank {privacy['rank']} · blocked"
    return "not re-id · verified" if privacy["verified"] else "not re-id · blocked"


def observed_boundary_handling(result: dict[str, Any]) -> str:
    if not result["privacy"]["realistic"]["verified"]:
        return "realistic_privacy_block"
    if not result["utility"]["equivalent"]:
        if int(result["privacy"]["realistic"].get("edits", 0)) == 0:
            return "surrogate_only_utility_miss"
        return "silent_utility_degradation"
    if not result["privacy"]["closed_world"]["verified"]:
        return "closed_world_stress_boundary"
    return "not_triggered"


def _trace_conflicts(events: list[dict[str, Any]]) -> str:
    facts = list(
        dict.fromkeys(
            str(fact)
            for event in events
            for fact in event.get("conflicting_facts", [])
            if str(fact)
        )
    )
    return " | ".join(facts[:5])


def write_report(path: Path, corpus: AcceptanceCorpus, results: dict[str, Any]) -> None:
    scenario_results: dict[str, Any] = results["scenarios"]
    complete = all(cache_is_current(scenario_results.get(case.scenario_id), case) for case in corpus.scenarios)
    scored = [
        scenario_results[case.scenario_id]
        for case in corpus.scenarios
        if cache_is_current(scenario_results.get(case.scenario_id), case)
    ]
    average_utility = sum(int(item["utility"]["score"]) for item in scored) / len(scored) if scored else 0.0
    auxiliary_free_passes = sum(
        not bool(item["privacy"]["auxiliary_free"]["reidentified"])
        and bool(item["privacy"]["auxiliary_free"]["verified"])
        for item in scored
    )
    realistic_passes = sum(
        not bool(item["privacy"]["realistic"]["reidentified"])
        and bool(item["privacy"]["realistic"]["verified"])
        for item in scored
    )
    closed_world_passes = sum(
        not bool(item["privacy"]["closed_world"]["reidentified"])
        and bool(item["privacy"]["closed_world"]["verified"])
        for item in scored
    )
    utility_equivalent = sum(bool(item["utility"]["equivalent"]) for item in scored)
    same_practical_value = sum(bool(item["utility"]["same_practical_value"]) for item in scored)
    restore_exact = sum(bool(item["restore"]["exact_for_answer_tokens"]) for item in scored)
    restore_clean = sum(
        bool(item["restore"]["exact_for_answer_tokens"])
        and not item["restore"]["missing_source_tokens"]
        and not item["restore"]["duplicated_tokens"]
        and not item["restore"]["mutated_tokens"]
        and not item["restore"]["unknown_tokens"]
        for item in scored
    )
    workflow_passes = sum(
        bool(item["privacy"]["realistic"]["verified"])
        and not bool(item["privacy"]["realistic"]["reidentified"])
        and bool(item["utility"]["equivalent"])
        and bool(item["restore"]["exact_for_answer_tokens"])
        for item in scored
    )
    honest_realistic_blocks = sum(not bool(item["privacy"]["realistic"]["verified"]) for item in scored)
    closed_world_blocks = sum(not bool(item["privacy"]["closed_world"]["verified"]) for item in scored)
    silent_degradations = sum(
        observed_boundary_handling(item) == "silent_utility_degradation"
        for item in scored
    )
    surrogate_only_utility_misses = sum(
        observed_boundary_handling(item) == "surrogate_only_utility_miss"
        for item in scored
    )
    web_search_calls = sum(int(item["privacy"]["realistic"].get("web_search_calls", 0)) for item in scored)
    current_result_calls = sum(int(item.get("remote_calls", 0)) for item in scored)
    archived_result_calls = sum(
        int(attempt.get("result", {}).get("remote_calls", 0))
        for attempt in results.get("attempt_history", [])
        if isinstance(attempt, dict) and isinstance(attempt.get("result"), dict)
    )
    legacy_unattributed_calls = int(results.get("legacy_unattributed_remote_calls", 0))
    failed_attempt_calls = sum(
        int(attempt.get("remote_calls", 0))
        for attempt in results.get("failed_attempts", [])
        if isinstance(attempt, dict)
    )
    lines = [
        "# Admissible real-world scenario acceptance",
        "",
        f"- Date: {datetime.now().astimezone().date().isoformat()}",
        f"- Status: **{'complete' if complete else 'partial'}**",
        f"- Scenarios scored: {len(scored)}/{len(corpus.scenarios)}",
        (
            f"- Primary web-enabled auxiliary-linkage privacy passes: {realistic_passes}/{len(scored)} "
            f"({AUXILIARY_POOL_SIZE} candidates per scenario; {web_search_calls} web-search tool calls)"
        ),
        f"- Auxiliary-free fictional-persona protocol passes: {auxiliary_free_passes}/{len(scored)}",
        f"- Worst-case closed-world privacy passes: {closed_world_passes}/{len(scored)}",
        f"- Strict utility equivalence: {utility_equivalent}/{len(scored)}; mean score {average_utility:.1f}/100",
        f"- Same practical value: {same_practical_value}/{len(scored)}",
        f"- Exact restoration for tokens used in answers: {restore_exact}/{len(scored)}",
        f"- Clean restoration diagnostics: {restore_clean}/{len(scored)}",
        f"- Whole-workflow acceptance: {workflow_passes}/{len(scored)}",
        (
            f"- Honest blocks: realistic {honest_realistic_blocks}/{len(scored)}, closed-world "
            f"{closed_world_blocks}/{len(scored)}; inference-edit utility degradations: {silent_degradations}; "
            f"surrogate-only utility misses: {surrogate_only_utility_misses}"
        ),
        f"- Execution remote calls, including superseded runs: {results.get('execution_remote_calls', 0)}",
        (
            f"- Call provenance: current results {current_result_calls}; archived attempts {archived_result_calls}; "
            f"failed/interrupted attempts {failed_attempt_calls}; legacy pre-history calls {legacy_unattributed_calls}"
        ),
        "",
        (
            "This suite tests the whole private-person workflow, not just controller correctness or public-figure "
            "re-identification. GPT-5.6 performs the real task on raw and sanitized documents using the same task "
            "prompt; a separate strict GPT-5.6 judgment compares substantive value after local restoration."
        ),
        "",
        (
            "The primary privacy tier is now a stronger evaluation stressor: GPT-5.6 gets web search plus a "
            f"{AUXILIARY_POOL_SIZE}-person synthetic population standing in for broker, employer, merchant, and "
            "case-record attributes. The former auxiliary-free fictional-persona test remains a separate tier, and "
            "the unchanged four-person roster remains the explicit worst-case controller stress tier."
        ),
        "",
        (
            "A `surrogate_only_utility_miss` means the paired answer failed the strict utility gate even "
            "though Admissible "
            "made no inference edit and preserved the document's substantive facts. The failure still counts, but "
            "it is not attributed to deleted task content. Natural surrogate effects and one-shot answer variance "
            "remain possible causes."
        ),
        "",
        "## Outcomes",
        "",
        "| Scenario | Web + 64 linkage | Auxiliary-free | Closed-world stress | Utility | Restore | Boundary |",
        "|---|---|---|---|---:|---|---|",
    ]
    for case in corpus.scenarios:
        result = scenario_results.get(case.scenario_id)
        if not cache_is_current(result, case):
            lines.append(f"| `{case.scenario_id}` | not run | not run | not run | — | — | — |")
            continue
        assert isinstance(result, dict)
        restore_payload = result["restore"]
        if not restore_payload["exact_for_answer_tokens"]:
            restore_label = "failed"
        elif restore_payload["duplicated_tokens"]:
            restore_label = "exact · duplicate references flagged"
        else:
            restore_label = "exact"
        utility = result["utility"]
        lines.append(
            f"| `{case.scenario_id}` | {_privacy_cell(result['privacy']['realistic'])} | "
            f"{_privacy_cell(result['privacy']['auxiliary_free'])} | "
            f"{_privacy_cell(result['privacy']['closed_world'])} | "
            f"{utility['score']}/100 · {utility['label']} | {restore_label} | "
            f"{observed_boundary_handling(result)} |"
        )

    lines.extend(["", "## Scenario detail", ""])
    for case in corpus.scenarios:
        result = scenario_results.get(case.scenario_id)
        if not cache_is_current(result, case):
            continue
        assert isinstance(result, dict)
        realistic = result["privacy"]["realistic"]
        auxiliary_free = result["privacy"]["auxiliary_free"]
        closed_world = result["privacy"]["closed_world"]
        utility = result["utility"]
        restore = result["restore"]
        source = f"[{case.source_title}]({case.source_url})" if case.source_url else case.source_title
        lines.extend(
            [
                f"### {case.scenario_id}",
                "",
                f"- Source: {source}; `{case.source_kind}`.",
                f"- User task: {case.task}",
                (
                    f"- Primary web-enabled linkage privacy: re-identified `{realistic['reidentified']}`; rank "
                    f"`{realistic['rank']}`; final `{realistic['final_phase']}`; population "
                    f"{realistic['auxiliary_population_size']}; {realistic['calls']} GPT-5.6 call and "
                    f"{realistic['web_search_calls']} web-search tool calls."
                ),
                (
                    f"- Auxiliary-free fictional-persona tier: re-identified `{auxiliary_free['reidentified']}`; "
                    f"rank `{auxiliary_free['rank']}`; final `{auxiliary_free['final_phase']}`; "
                    f"{auxiliary_free['edits']} edits and {auxiliary_free['calls']} attacker calls."
                ),
                (
                    f"- Closed-world stress: re-identified `{closed_world['reidentified']}`; rank "
                    f"`{closed_world['rank']}`; final `{closed_world['final_phase']}`; "
                    f"{closed_world['edits']} edits and {closed_world['calls']} attacker calls."
                ),
                (
                    "- Closed-world conflicting facts: "
                    f"{_trace_conflicts(result['trace_events']['closed_world']) or 'none'}."
                ),
                (
                    f"- Utility: **{utility['score']}/100 ({utility['label']})** — coverage "
                    f"{utility['risk_issue_coverage']}/40, advice {utility['advice_fidelity']}/30, "
                    f"actionability {utility['actionability']}/20, factual consistency "
                    f"{utility['factual_consistency']}/10. Same practical value: `{utility['same_practical_value']}`."
                ),
                f"- Critical omissions: {utility['critical_omissions'] or 'none'}.",
                f"- Substantive distortions: {utility['substantive_distortions'] or 'none'}.",
                f"- Judge rationale: {utility['rationale']}",
                (
                f"- Restore: exact for all {restore['answer_token_occurrences']} surrogate occurrences used in the "
                    f"answer: `{restore['exact_for_answer_tokens']}`; restored {restore['restored_count']}. Missing "
                    f"source tokens not used by the answer: {len(restore['missing_source_tokens'])}; duplicated "
                    f"references {len(restore['duplicated_tokens'])}; mutated {len(restore['mutated_tokens'])}; "
                    f"unknown {len(restore['unknown_tokens'])}."
                ),
                f"- Boundary expectation: {case.boundary_note}",
                f"- Boundary handling observed: `{observed_boundary_handling(result)}`.",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation limits",
            "",
            "- All protected subjects and auxiliary-roster entries are fictional private personas.",
            (
                "- Public documents supply clause/layout realism only; sensitive medical, immigration, and workplace "
                "facts are synthetic."
            ),
            (
                "- The web-enabled tier still uses synthetic people and a synthetic candidate population. It is a "
                "more realistic linkage stress test, not a measured population anonymity rate or a substitute for "
                "testing with consented people who have real public and commercial traces."
            ),
            "- The auxiliary-free tier is retained for comparability but remains weak evidence for fictional people.",
            "- The four-person closed-world roster is deliberately adversarial and is not a population estimate.",
            (
                "- The raw task answer, restored answer, and roster leave the machine only in this explicit synthetic "
                "evaluation harness; this is not a product egress path."
            ),
            (
                "- GPT-5.6 generated both task answers and judged utility. The structured rubric and required-findings "
                "list make the comparison strict, but it is not an independent human or cross-model judgment."
            ),
            (
                "- Restoration is scored on surrogate occurrences the task answer actually uses. A task model may "
                "legitimately omit an email or account number; those are reported as missing source tokens rather "
                "than treated as incorrect substitution."
            ),
            "- Medical and legal scenario outputs evaluate task preservation only and are not medical or legal advice.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def select_cases(corpus: AcceptanceCorpus, mode: str, requested: list[str]) -> list[AcceptanceCase]:
    ids = requested or ([SANITY_SCENARIO_ID] if mode == "sanity" else [])
    if not ids:
        return corpus.scenarios
    by_id = {case.scenario_id: case for case in corpus.scenarios}
    missing = [case_id for case_id in ids if case_id not in by_id]
    if missing:
        raise ValueError(f"Unknown scenario IDs: {missing}")
    return [by_id[case_id] for case_id in ids]


async def async_main() -> int:
    parser = argparse.ArgumentParser(description="Run Admissible's bounded real-world workflow acceptance suite.")
    parser.add_argument("mode", choices=("sanity", "full"))
    parser.add_argument("--scenario-id", action="append", default=[], dest="scenario_ids")
    parser.add_argument("--max-new-remote-calls", type=int, default=20)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    corpus = load_corpus()
    selected = select_cases(corpus, args.mode, args.scenario_ids)
    results = load_results(args.results)
    cached = all(cache_is_current(results["scenarios"].get(case.scenario_id), case) for case in selected)
    if cached:
        changed = False
        for case in selected:
            current = results["scenarios"].get(case.scenario_id)
            if isinstance(current, dict):
                boundary = observed_boundary_handling(current)
                if current.get("boundary_handling") != boundary:
                    current["boundary_handling"] = boundary
                    changed = True
        if changed:
            results["updated_at"] = datetime.now(UTC).isoformat()
            atomic_write_json(args.results, results)
        write_report(args.report, corpus, results)
        print(json.dumps({"mode": args.mode, "selected": len(selected), "new_remote_calls": 0}))
        return 0

    anonymizer = OllamaAnonymizer()
    if not await anonymizer.ready():
        raise RuntimeError(f"Ollama model {anonymizer.model} is not ready.")
    budget = RemoteBudget(args.max_new_remote_calls)
    remote = AcceptanceRemote(budget)
    try:
        for case in selected:
            current = results["scenarios"].get(case.scenario_id)
            if cache_is_current(current, case):
                continue
            budget.reserve_scenario()
            calls_before = budget.used
            try:
                outcome = await run_scenario(case, remote)
            except BaseException as exc:
                consumed = budget.used - calls_before
                record_failed_attempt(
                    results,
                    scenario_id=case.scenario_id,
                    calls=consumed,
                    error_type=type(exc).__name__,
                )
                results["execution_remote_calls"] = int(results.get("execution_remote_calls", 0)) + consumed
                results["updated_at"] = datetime.now(UTC).isoformat()
                atomic_write_json(args.results, results)
                write_report(args.report, corpus, results)
                raise
            if isinstance(current, dict):
                archive_superseded_result(results, case.scenario_id, current)
            results["scenarios"][case.scenario_id] = outcome
            results["controller_protocol_version"] = CONTROLLER_PROTOCOL_VERSION
            results["execution_remote_calls"] = int(results.get("execution_remote_calls", 0)) + int(
                outcome["remote_calls"]
            )
            results["updated_at"] = datetime.now(UTC).isoformat()
            atomic_write_json(args.results, results)
            print(
                json.dumps(
                    {
                        "scenario": case.scenario_id,
                        "auxiliary_free_reidentified": outcome["privacy"]["auxiliary_free"]["reidentified"],
                        "auxiliary_free_verified": outcome["privacy"]["auxiliary_free"]["verified"],
                        "realistic_reidentified": outcome["privacy"]["realistic"]["reidentified"],
                        "realistic_verified": outcome["privacy"]["realistic"]["verified"],
                        "closed_world_reidentified": outcome["privacy"]["closed_world"]["reidentified"],
                        "closed_world_verified": outcome["privacy"]["closed_world"]["verified"],
                        "utility": outcome["utility"]["score"],
                        "restore": outcome["restore"]["exact_for_answer_tokens"],
                        "calls": outcome["remote_calls"],
                        "new_calls_used": budget.used,
                    }
                ),
                flush=True,
            )
    finally:
        await remote.close()

    write_report(args.report, corpus, results)
    print(
        json.dumps(
            {
                "mode": args.mode,
                "selected": len(selected),
                "new_remote_calls": budget.used,
                "results": str(args.results),
                "report": str(args.report),
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(async_main()))
    except (RuntimeError, ValueError) as exc:
        print(f"scenario acceptance stopped: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
