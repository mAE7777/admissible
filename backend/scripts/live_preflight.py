from __future__ import annotations

import json
import time

import httpx

BASE_URL = "http://127.0.0.1:8787"
SUBJECT = "Maryam Mirzakhani"
ALIAS = "Mirzakhani"
DOCUMENT = (
    "Maryam Mirzakhani developed influential work in hyperbolic geometry and dynamical systems. "
    "In 2014, she became the first woman to receive the Fields Medal. The document should be "
    "summarized for a university mathematics newsletter while preserving the research areas and "
    "the significance of the recognition. The requested summary should explain the work to readers "
    "without specialized training. Keep the tone factual, describe why the research mattered, and "
    "avoid biographical trivia unrelated to the mathematics. The final response needs one paragraph "
    "for the research contribution and one for the award's broader significance."
)


def parse_events(body: str) -> list[dict[str, object]]:
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


def main() -> int:
    with httpx.Client(base_url=BASE_URL, timeout=240.0) as client:
        health = client.get("/api/health")
        health.raise_for_status()
        health_payload = health.json()
        if not health_payload["ollama_ready"] or not health_payload["attacker_ready"]:
            raise RuntimeError("Admissible dependencies are not both ready.")

        created = client.post("/api/sessions", json={"text": DOCUMENT})
        created.raise_for_status()
        session_id = created.json()["session_id"]
        try:
            confirmed = client.post(
                f"/api/sessions/{session_id}/confirm",
                json={
                    "subject": {"canonical_identity": SUBJECT, "aliases": [ALIAS]},
                    "identifiers": [],
                    "pins": ["university mathematics newsletter"],
                },
            )
            confirmed.raise_for_status()
            initial = confirmed.json()["candidate"]
            if SUBJECT in initial["text"] or ALIAS in initial["text"]:
                raise RuntimeError("Confirmed subject survived local tokenization.")

            response = client.post(f"/api/sessions/{session_id}/runs")
            response.raise_for_status()
            events = parse_events(response.text)
            if not events:
                raise RuntimeError("The live controller returned no trace events.")

            models: set[str] = set()
            max_calls = 0
            for event in events:
                max_calls = max(max_calls, int(event["calls_used"]))
                attack = event.get("attack")
                if isinstance(attack, dict):
                    returned_model = str(attack["returned_model"])
                    models.add(returned_model)
                    if not (returned_model == "gpt-5.6" or returned_model.startswith("gpt-5.6-sol")):
                        raise RuntimeError(f"Unexpected returned model: {returned_model}")
                evidence = event.get("evidence")
                grounding = []
                grounded_quotes = []
                if isinstance(evidence, list):
                    grounding = [str(item["status"]) for item in evidence if isinstance(item, dict)]
                    grounded_quotes = [
                        str(item["quote"])
                        for item in evidence
                        if isinstance(item, dict) and item["status"] == "grounded"
                    ]
                utility = event.get("utility")
                utility_status = None
                edit_ratio = None
                if isinstance(utility, dict):
                    utility_status = bool(utility["accepted"])
                    edit_ratio = round(float(utility["cumulative_edit_ratio"]), 4)
                print(
                    json.dumps(
                        {
                            "phase": event["phase"],
                            "status": event["status"],
                            "calls": event["calls_used"],
                            "grounding": grounding,
                            "grounded_quotes": grounded_quotes,
                            "utility_accepted": utility_status,
                            "cumulative_edit_ratio": edit_ratio,
                            "replacement": (
                                event["patch"]["replacement"] if isinstance(event.get("patch"), dict) else None
                            ),
                        }
                    ),
                    flush=True,
                )

            if not models:
                raise RuntimeError("No credentialed attacker result was observed.")
            if max_calls > 8:
                raise RuntimeError("Attacker call ceiling was exceeded.")

            final = events[-1]
            causal_calls = 0
            if final["phase"] == "run_passed":
                patch_events = [event for event in events if event["phase"] == "patch_accepted"]
                if patch_events and max_calls + 2 <= 5:
                    causal_quote = patch_events[-1]["evidence"][0]["quote"]
                    run_id = str(events[0]["event_id"]).split(":", maxsplit=1)[0]
                    causal_started = time.monotonic()
                    causal = client.post(
                        f"/api/sessions/{session_id}/runs/{run_id}/causal",
                        json={"quote": causal_quote},
                    )
                    causal.raise_for_status()
                    causal_payload = causal.json()
                    causal_calls = int(causal_payload["calls_used"])
                    for attack_name in ("counterfactual", "control"):
                        returned_model = causal_payload[attack_name]["returned_model"]
                        if not (returned_model == "gpt-5.6" or returned_model.startswith("gpt-5.6-sol")):
                            raise RuntimeError(f"Unexpected causal-test model: {returned_model}")
                    print(
                        json.dumps(
                            {
                                "causal_verdict": causal_payload["verdict"],
                                "causal_calls": causal_calls,
                                "causal_wall_seconds": round(time.monotonic() - causal_started, 2),
                            }
                        ),
                        flush=True,
                    )
                elif patch_events:
                    print(json.dumps({"causal_skipped": "five-call nominal ceiling"}), flush=True)
            if max_calls + causal_calls > 5:
                raise RuntimeError("Core and causal calls exceeded the five-call nominal ceiling.")

            candidate = final.get("candidate")
            if not isinstance(candidate, dict) or not isinstance(candidate.get("text"), str):
                raise RuntimeError("Final trace event omitted the sanitized candidate.")
            restored = client.post(f"/api/sessions/{session_id}/restore", json={"text": candidate["text"]})
            restored.raise_for_status()
            restore_payload = restored.json()
            if SUBJECT not in restore_payload["restored_text"]:
                raise RuntimeError("Known subject token did not restore locally.")
            if any(
                restore_payload[field]
                for field in (
                    "missing_tokens",
                    "duplicated_tokens",
                    "mutated_tokens",
                    "unknown_tokens",
                )
            ):
                raise RuntimeError("Restore diagnostics reported token corruption.")

            print(
                json.dumps(
                    {
                        "outcome": final["phase"],
                        "models": sorted(models),
                        "core_calls": max_calls,
                        "total_calls": max_calls + causal_calls,
                        "restored_count": restore_payload["restored_count"],
                        "restore_diagnostics": "clean",
                    }
                )
            )
            return 0
        finally:
            client.delete(f"/api/sessions/{session_id}")


if __name__ == "__main__":
    raise SystemExit(main())
