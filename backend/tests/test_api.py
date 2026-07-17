from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cloak.main import app


def test_health_never_exposes_secrets() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "status",
        "ollama_ready",
        "ollama_model",
        "attacker_ready",
        "attacker_model",
        "privacy_boundary",
    }
    assert "key" not in response.text.lower()


def test_recorded_trace_is_unambiguously_synthetic() -> None:
    with TestClient(app) as client:
        response = client.get("/api/demo-runs/harbor")
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "Recorded · synthetic"
    assert all(event["mode"] == "recorded" for event in payload["events"])


def test_recorded_refusal_names_the_exact_task_conflict_without_editing() -> None:
    with TestClient(app) as client:
        response = client.get("/api/demo-runs/task-conflict")
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "Recorded · synthetic task conflict"
    final = payload["events"][-1]
    assert final["phase"] == "run_blocked"
    assert final["conflicting_facts"]
    assert final["candidate"]["pass_number"] == 0
    assert all(event["patch"] is None for event in payload["events"])


@pytest.mark.parametrize("slug", ["harbor", "task-conflict"])
def test_recorded_demo_candidates_never_contain_the_protected_identity(slug: str) -> None:
    with TestClient(app) as client:
        payload = client.get(f"/api/demo-runs/{slug}").json()
    subject = payload["protected_subject"].casefold()
    assert all(subject not in event["candidate"]["text"].casefold() for event in payload["events"])


def test_unknown_recorded_demo_is_not_found() -> None:
    with TestClient(app) as client:
        response = client.get("/api/demo-runs/not-real")
    assert response.status_code == 404


def test_session_rejects_empty_and_oversized_documents() -> None:
    with TestClient(app) as client:
        assert client.post("/api/sessions", json={"text": "  "}).status_code == 422
        assert client.post("/api/sessions", json={"text": "x" * 12_001}).status_code == 422


def test_confirmation_requires_a_real_downstream_task() -> None:
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": "Mara Voss wrote a report."}).json()
        response = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "Mara Voss", "aliases": []},
                "identifiers": [],
                "pins": [],
            },
        )
    assert response.status_code == 422


@pytest.mark.parametrize("fake_identifier", ["$612.00", "14 June 2026", "40 mg"])
def test_confirmation_rejects_task_facts_submitted_as_arbitrary_identifiers(fake_identifier: str) -> None:
    document = (
        "Mara Voss prepared the English review on 14 June 2026. The invoice was $612.00, and the "
        "clinical note records 40 mg every other week. Keep each amount, date, and dose exact."
    )
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": document}).json()
        response = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "Mara Voss", "aliases": []},
                "identifiers": [fake_identifier],
                "pins": [],
                "task": "Review the amount, date, and dose without changing any of them.",
            },
        )
    assert response.status_code == 422
    assert "local identifier suggestions" in response.json()["detail"]


@pytest.mark.parametrize("fake_alias", ["$612.00", "14 June 2026", "40 mg"])
def test_confirmation_rejects_task_facts_submitted_as_subject_aliases(fake_alias: str) -> None:
    document = (
        "Mara Voss prepared the English review on 14 June 2026. The invoice was $612.00, and the "
        "clinical note records 40 mg every other week. Keep each amount, date, and dose exact."
    )
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": document}).json()
        response = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "Mara Voss", "aliases": [fake_alias]},
                "identifiers": [],
                "pins": [],
                "task": "Review the amount, date, and dose without changing any of them.",
            },
        )
    assert response.status_code == 422
    assert "alias must be name-like" in response.json()["detail"]


def test_confirmation_rejects_an_arbitrary_role_as_the_protected_subject() -> None:
    document = "Mara Voss serves as Director. Preserve the exact role while reviewing this English agreement."
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": document}).json()
        response = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "Director", "aliases": []},
                "identifiers": [],
                "pins": [],
                "task": "Review the agreement and preserve the exact role.",
            },
        )
    assert response.status_code == 422
    assert "local person suggestions" in response.json()["detail"]


def test_confirmation_rejects_non_english_document_and_task() -> None:
    with TestClient(app) as client:
        created = client.post(
            "/api/sessions",
            json={"text": "María López redactó el informe y mantuvo la cronología exacta para la revisión."},
        ).json()
        response = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "María López", "aliases": []},
                "identifiers": [],
                "pins": [],
                "task": "Resume quién hizo qué y cuándo.",
            },
        )
    assert response.status_code == 422
    assert response.json()["detail"] == "Cloak currently supports English documents and tasks only."
