from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from admissible.controller import CONTROLLER_PROTOCOL_VERSION  # noqa: E402
from admissible.sessions import SessionStore  # noqa: E402
from scripts.scenario_acceptance import (  # noqa: E402
    COMMITTED_CORPUS_SHA256,
    DEFAULT_CASES,
    LINKAGE_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    RemoteBudget,
    UtilityJudgment,
    archive_superseded_result,
    cache_is_current,
    case_fingerprint,
    load_corpus,
    observed_boundary_handling,
    record_failed_attempt,
    score_utility_judgment,
    synthetic_auxiliary_population,
    write_report,
)


def test_acceptance_corpus_covers_private_real_world_scenarios() -> None:
    corpus = load_corpus()
    assert corpus.schema_version == PROTOCOL_VERSION
    assert len(corpus.scenarios) == 5
    assert Counter(case.category for case in corpus.scenarios) == {
        "contract": 1,
        "medical_record": 1,
        "immigration_narrative": 1,
        "financial_statement": 1,
        "hr_workplace_complaint": 1,
    }
    assert all(case.private_persona for case in corpus.scenarios)
    assert all(case.language == "en" for case in corpus.scenarios)
    assert all(len(case.auxiliary_roster) == 4 for case in corpus.scenarios)
    assert hashlib.sha256(DEFAULT_CASES.read_bytes()).hexdigest() == COMMITTED_CORPUS_SHA256


def test_case_fingerprint_covers_document_task_roster_and_expected_findings() -> None:
    case = load_corpus().scenarios[0]
    baseline = case_fingerprint(case)
    variants = [
        case.model_copy(update={"document": f"{case.document}\nchanged"}),
        case.model_copy(update={"task": f"{case.task} changed"}),
        case.model_copy(update={"expected_findings": [*case.expected_findings, "changed"]}),
        case.model_copy(
            update={
                "auxiliary_roster": [
                    *case.auxiliary_roster[:-1],
                    case.auxiliary_roster[-1].model_copy(update={"profile": "changed"}),
                ]
            }
        ),
    ]
    assert all(case_fingerprint(variant) != baseline for variant in variants)


def test_every_scenario_direct_identifier_is_a_local_confirmation_suggestion() -> None:
    store = SessionStore()
    for case in load_corpus().scenarios:
        created = store.create(case.document)
        suggestions = {candidate.value for candidate in created.identifier_candidates}
        assert set(case.direct_identifiers) <= suggestions
        assert case.protected_subject.canonical_identity in created.subject_suggestions


def test_remote_budget_reserves_full_scenario_before_any_call() -> None:
    budget = RemoteBudget(20)
    budget.reserve_scenario()
    for _ in range(20):
        budget.consume()
    with pytest.raises(RuntimeError, match="exhausted"):
        budget.consume()
    with pytest.raises(RuntimeError, match="would be exceeded"):
        budget.reserve_scenario()


def test_strict_utility_score_requires_85_and_no_critical_gap() -> None:
    metadata = {"returned_model": "gpt-5.6-sol", "latency_ms": 1, "usage": {}}
    eighty_four = UtilityJudgment(
        risk_issue_coverage=34,
        advice_fidelity=25,
        actionability=17,
        factual_consistency=8,
        same_practical_value=True,
        rationale="Useful but below the strict same-value threshold.",
    )
    assert score_utility_judgment(eighty_four, metadata)["label"] == "partial"

    eighty_five_with_gap = eighty_four.model_copy(
        update={"risk_issue_coverage": 35, "critical_omissions": ["Missed the central risk."]}
    )
    assert score_utility_judgment(eighty_five_with_gap, metadata)["equivalent"] is False

    equivalent = eighty_five_with_gap.model_copy(update={"critical_omissions": []})
    scored = score_utility_judgment(equivalent, metadata)
    assert scored["score"] == 85
    assert scored["label"] == "equivalent"
    assert scored["equivalent"] is True


def test_scenario_fixture_is_valid_json_with_no_public_subject_flag() -> None:
    payload = json.loads(load_corpus().model_dump_json())
    assert all(item["private_persona"] is True for item in payload["scenarios"])


def test_completed_cache_rejects_any_non_gpt_56_returned_model() -> None:
    case = load_corpus().scenarios[0]
    product_text = "Natural surrogate product candidate."
    product_hash = hashlib.sha256(product_text.encode()).hexdigest()
    closed_text = "Natural surrogate closed-world candidate."
    closed_hash = hashlib.sha256(closed_text.encode()).hexdigest()
    result = {
        "status": "ok",
        "case_fingerprint": case_fingerprint(case),
        "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
        "task_prompt_version": "cloak-scenario-task-2026-07-16.v4",
        "linkage_protocol_version": LINKAGE_PROTOCOL_VERSION,
        "category": case.category,
        "language": "en",
        "private_persona": True,
        "privacy": {
            "auxiliary_free": {
                "returned_models": ["gpt-5.6-sol"],
                "reidentified": False,
                "rank": None,
                "verified": True,
                "final_phase": "run_passed",
                "calls": 2,
                "candidate_sha256": product_hash,
            },
            "realistic": {
                "returned_models": ["gpt-5.6-sol"],
                "reidentified": True,
                "rank": 1,
                "verified": False,
                "final_phase": "linkage_blocked",
                "calls": 1,
                "web_search_calls": 1,
                "auxiliary_population_size": 64,
                "edits": 0,
                "candidate_sha256": product_hash,
                "threat_model": "web search plus synthetic broker/employer/merchant/case-record linkage population",
            },
            "closed_world": {
                "returned_models": ["gpt-5.6-sol"],
                "reidentified": True,
                "rank": 1,
                "verified": False,
                "final_phase": "run_blocked",
                "calls": 1,
                "candidate_sha256": closed_hash,
            },
        },
        "raw_task_answer": {"returned_model": "gpt-5.6-sol"},
        "sanitized_task_answer": {"returned_model": "gpt-5.6-sol"},
        "utility": {"returned_model": "gpt-5.6-sol"},
        "final_sanitized_candidate": {"text": product_text, "sha256": product_hash},
        "closed_world_final_candidate": {"text": closed_text, "sha256": closed_hash},
        "remote_calls": 7,
    }
    assert cache_is_current(result, case)

    for path in (
        ("privacy.auxiliary_free", "returned_models"),
        ("privacy.realistic", "returned_models"),
        ("privacy.closed_world", "returned_models"),
        ("raw_task_answer", "returned_model"),
        ("sanitized_task_answer", "returned_model"),
        ("utility", "returned_model"),
    ):
        poisoned = deepcopy(result)
        if path[0].startswith("privacy."):
            _, tier = path[0].split(".")
            poisoned["privacy"][tier][path[1]] = ["gpt-4.1"]
        else:
            poisoned[path[0]][path[1]] = "gpt-4.1"
        assert cache_is_current(poisoned, case) is False

    evidence_tampering = (
        ("auxiliary_population_size", 4),
        ("web_search_calls", 0),
        ("calls", 0),
        ("rank", None),
        ("final_phase", "linkage_passed"),
    )
    for field, value in evidence_tampering:
        poisoned = deepcopy(result)
        poisoned["privacy"]["realistic"][field] = value
        assert cache_is_current(poisoned, case) is False

    poisoned = deepcopy(result)
    poisoned["remote_calls"] = 6
    assert cache_is_current(poisoned, case) is False

    for malformed_web_calls in (True, "1"):
        poisoned = deepcopy(result)
        poisoned["privacy"]["realistic"]["web_search_calls"] = malformed_web_calls
        assert cache_is_current(poisoned, case) is False

    poisoned = deepcopy(result)
    poisoned["final_sanitized_candidate"]["text"] = "tampered candidate"
    assert cache_is_current(poisoned, case) is False

    poisoned = deepcopy(result)
    poisoned["final_sanitized_candidate"]["sha256"] = "bad"
    poisoned["privacy"]["auxiliary_free"]["candidate_sha256"] = "bad"
    poisoned["privacy"]["realistic"]["candidate_sha256"] = "bad"
    assert cache_is_current(poisoned, case) is False


def test_boundary_attribution_separates_surrogate_only_miss_from_inference_degradation() -> None:
    result = {
        "privacy": {
            "realistic": {"verified": True, "edits": 0},
            "closed_world": {"verified": False},
        },
        "utility": {"equivalent": False},
    }
    assert observed_boundary_handling(result) == "surrogate_only_utility_miss"

    result["privacy"]["realistic"]["edits"] = 1
    assert observed_boundary_handling(result) == "silent_utility_degradation"


def test_linkage_population_is_deterministic_large_and_contains_the_private_subject() -> None:
    case = load_corpus().scenarios[0]
    first = synthetic_auxiliary_population(case)
    second = synthetic_auxiliary_population(case)
    assert len(first) == 64
    assert first == second
    assert len({entry.identity for entry in first}) == 64
    assert case.protected_subject.canonical_identity in {entry.identity for entry in first}
    assert all(entry.profile for entry in first)


def test_report_marks_stale_pre_linkage_rows_not_run_instead_of_dereferencing_them(tmp_path: Path) -> None:
    corpus = load_corpus()
    case = corpus.scenarios[0]
    stale = {
        "status": "ok",
        "case_fingerprint": case_fingerprint(case),
        "controller_protocol_version": "cloak-core-old",
        "privacy": {"realistic": {}, "closed_world": {}},
        "utility": {"score": 100},
    }
    report = tmp_path / "report.md"
    write_report(report, corpus, {"scenarios": {case.scenario_id: stale}})
    rendered = report.read_text(encoding="utf-8")
    assert "Status: **partial**" in rendered
    assert f"| `{case.scenario_id}` | not run | not run | not run |" in rendered


def test_failed_attempt_history_is_bounded_and_retains_remote_call_provenance() -> None:
    results: dict[str, object] = {}
    for index in range(55):
        record_failed_attempt(
            results,  # type: ignore[arg-type]
            scenario_id=f"case-{index}",
            calls=index,
            error_type="TimeoutError",
        )
    failures = results["failed_attempts"]
    assert isinstance(failures, list)
    assert len(failures) == 50
    assert failures[0]["scenario_id"] == "case-5"
    assert failures[-1]["remote_calls"] == 54


def test_superseded_result_history_is_bounded() -> None:
    results: dict[str, object] = {}
    for index in range(55):
        archive_superseded_result(
            results,  # type: ignore[arg-type]
            f"case-{index}",
            {"remote_calls": index},
        )
    history = results["attempt_history"]
    assert isinstance(history, list)
    assert len(history) == 50
    assert history[0]["scenario_id"] == "case-5"
