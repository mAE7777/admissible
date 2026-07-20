from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from admissible.main import app


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


def test_contextual_employer_is_an_organization_surrogate_and_restores_exactly() -> None:
    document = (
        "Case note. Jordan Okafor, route-analytics lead at Harborline Freight in Chicago, returned from parental "
        "leave on 3 February 2026."
    )
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": document}).json()
        harborline = [item for item in created["identifier_candidates"] if item["value"] == "Harborline Freight"]
        assert [item["label"] for item in harborline] == ["Organization"]
        assert "Harborline Freight" not in [
            item["value"] for item in created["identifier_candidates"] if item["label"] == "Person"
        ]

        confirmed = client.post(
            f"/api/sessions/{created['session_id']}/confirm",
            json={
                "subject": {"canonical_identity": "Jordan Okafor", "aliases": []},
                "identifiers": ["Harborline Freight"],
                "pins": [],
                "task": "Review the leave chronology and preserve the employer relationship.",
            },
        )
        assert confirmed.status_code == 200
        sanitized = confirmed.json()["candidate"]["text"]
        surrogate_match = re.search(r"lead at ([A-Z][a-z]+ Freight) in Chicago", sanitized)
        assert surrogate_match is not None
        assert surrogate_match.group(1) != "Harborline Freight"

        restored = client.post(
            f"/api/sessions/{created['session_id']}/restore",
            json={"text": sanitized},
        ).json()
        assert restored["restored_text"] == document
        assert restored["restored_count"] == 2
        diagnostic_keys = ("missing_tokens", "duplicated_tokens", "mutated_tokens", "unknown_tokens")
        assert not any(restored[key] for key in diagnostic_keys)


def test_address_recognizer_stops_at_real_address_boundaries() -> None:
    document = (
        "Case note. Jordan Okafor, route-analytics lead at Harborline Freight in Chicago, now lives at "
        "742 Cedar Avenue, Portland, OR 97205. He returned on 20 February and reported it to HR on 2 March. "
        "His email is jordan.okafor@example.com."
    )
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": document}).json()
    addresses = [item["value"] for item in created["identifier_candidates"] if item["label"] == "Address"]
    assert addresses == ["742 Cedar Avenue, Portland, OR 97205"]
    assert "Cedar Avenue" not in [
        item["value"] for item in created["identifier_candidates"] if item["label"] == "Person"
    ]


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
    assert response.json()["detail"] == "Admissible currently supports English documents and tasks only."


def test_cross_origin_state_change_is_rejected_before_the_controller_runs() -> None:
    """A loopback API is still reachable by any page in the user's browser.

    CORS only withholds the access-control header from the response; it does not stop the request
    being processed. `/runs` takes no body, so it is a CORS "simple" request (no preflight) and is
    not covered by strict-content-type validation either. It also spends the API budget and runs
    the live attack, so it is the one that must not be drivable cross-origin.
    """
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": "Case note. Jordan Okafor reported it to HR."}).json()
        session_id = created["session_id"]

        hostile = client.post(
            f"/api/sessions/{session_id}/runs",
            headers={"Origin": "https://evil.example"},
        )
        assert hostile.status_code == 403
        assert hostile.json()["detail"] == "Cross-origin request rejected."

        # The legitimate frontend origin is unaffected, and so is a non-browser caller with no
        # Origin at all (curl, the test client, local tooling) — those are guarded by the loopback
        # bind, and rejecting them would break local use for no security gain.
        for headers in ({"Origin": "http://127.0.0.1:5173"}, {}):
            allowed = client.post(f"/api/sessions/{session_id}/confirm", json={}, headers=headers)
            assert allowed.status_code != 403


def test_baseline_security_headers_are_present() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_restore_rejects_payloads_larger_than_a_pasted_document() -> None:
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"text": "Case note. Jordan Okafor reported it."}).json()
        oversized = client.post(
            f"/api/sessions/{created['session_id']}/restore",
            json={"text": "x" * 12_001},
        )
        assert oversized.status_code == 422
