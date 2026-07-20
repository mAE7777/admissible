from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import admissible.main as main_module
from admissible.benchmark import (
    load_benchmark_corpus,
    naive_direct_identifier_candidate,
    validate_result_cache_models,
)
from admissible.models import AttackResult, SanitizedEnvelope


class CapturingAttacker:
    def __init__(self, returned_model: str = "gpt-5.6-sol-2026-07-01") -> None:
        self.envelopes: list[SanitizedEnvelope] = []
        self.returned_model = returned_model

    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult:
        self.envelopes.append(envelope)
        return AttackResult(returned_model=self.returned_model, latency_ms=1)


def test_smoke_corpus_has_balanced_from_scratch_cases() -> None:
    corpus = load_benchmark_corpus()
    assert corpus.language == "en"
    assert "No external dataset" in corpus.provenance
    assert len(corpus.cases) == 15
    assert Counter(case.difficulty for case in corpus.cases) == {
        "direct_pii": 5,
        "single_distinctive_clue": 5,
        "aggregate_quasi_identifiers": 5,
    }


def test_presidio_naive_baseline_tokens_direct_values_but_keeps_indirect_clues() -> None:
    for case in load_benchmark_corpus().cases:
        candidate = naive_direct_identifier_candidate(case)
        protected_values = [
            case.protected_subject.canonical_identity,
            *case.protected_subject.aliases,
            *case.direct_identifiers,
        ]
        assert all(value not in candidate.text for value in protected_values)
        assert all(value in candidate.detected_values for value in case.direct_identifiers)
        assert candidate.token_count >= 2
        indirect_clues = [clue for clue in case.identifying_clues if clue not in protected_values]
        assert all(clue in candidate.text for clue in indirect_clues)


def test_benchmark_route_attacks_only_bundled_raw_or_naive_fixture(monkeypatch) -> None:
    fake = CapturingAttacker()
    monkeypatch.setattr(main_module, "attacker", fake)
    with TestClient(main_module.app) as client:
        raw = client.post("/api/benchmark-smoke/distinctive-alan-turing/raw", json={})
        naive = client.post("/api/benchmark-smoke/distinctive-alan-turing/direct_identifier_only", json={})
        missing = client.post("/api/benchmark-smoke/not-a-case/raw", json={})
        invalid = client.post("/api/benchmark-smoke/distinctive-alan-turing/admissible", json={})
        bodyless = client.post("/api/benchmark-smoke/distinctive-alan-turing/raw")
        document_injection = client.post(
            "/api/benchmark-smoke/distinctive-alan-turing/raw",
            json={"text": "not a bundled fixture"},
        )

    assert raw.status_code == 200
    assert naive.status_code == 200
    assert missing.status_code == 404
    assert invalid.status_code == 422
    assert bodyless.status_code == 422
    assert document_injection.status_code == 422
    assert len(fake.envelopes) == 2
    assert "Alan Turing" in fake.envelopes[0].candidate_text
    assert "Alan Turing" not in fake.envelopes[1].candidate_text
    assert "alan.turing@example.org" not in fake.envelopes[1].candidate_text
    assert "Bletchley Park" in fake.envelopes[1].candidate_text


def test_benchmark_route_rejects_wrong_returned_model(monkeypatch) -> None:
    monkeypatch.setattr(main_module, "attacker", CapturingAttacker("gpt-5.5"))
    with TestClient(main_module.app) as client:
        response = client.post("/api/benchmark-smoke/direct-ada-lovelace/raw", json={})
    assert response.status_code == 503
    assert "AttackerProtocolError" in response.json()["detail"]


def test_benchmark_cache_rejects_wrong_returned_model(tmp_path: Path) -> None:
    poisoned = {
        "schema_version": "cloak-benchmark-results-2026-07-15.v1",
        "attacker": "gpt-5.6",
        "execution_remote_calls": 1,
        "cases": {
            "poisoned-case": {
                "conditions": {
                    "raw": {
                        "status": "ok",
                        "returned_models": ["gpt-5.5"],
                    }
                }
            }
        },
    }
    path = tmp_path / "poisoned-results.json"
    path.write_text(json.dumps(poisoned), encoding="utf-8")
    with pytest.raises(ValueError, match="non-GPT-5.6 model"):
        validate_result_cache_models(json.loads(path.read_text(encoding="utf-8")))
