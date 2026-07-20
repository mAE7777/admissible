from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import httpx

from admissible.benchmark import (
    BenchmarkCase,
    corpus_fingerprint,
    load_benchmark_corpus,
    validate_result_cache_models,
)
from admissible.controller import CONTROLLER_PROTOCOL_VERSION
from admissible.models import AttackResult, BenchmarkAttackResponse
from admissible.privacy import identity_rank

BASE_URL = "http://127.0.0.1:8787"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS = REPO_ROOT / "qa-reports" / "benchmark-smoke-results.json"
DEFAULT_REPORT = REPO_ROOT / "qa-reports" / "benchmark-smoke-report.md"
Condition = Literal["raw", "direct_identifier_only", "cloak"]
CONDITIONS: tuple[Condition, ...] = ("raw", "direct_identifier_only", "cloak")
CONDITION_LABELS: tuple[tuple[Condition, str], ...] = (
    ("raw", "Raw synthetic document"),
    ("direct_identifier_only", "Presidio + opaque direct identifiers"),
    ("cloak", "Admissible core loop"),
)
SANITY_CASE_IDS = (
    "direct-ada-lovelace",
    "distinctive-alan-turing",
    "aggregate-satya-nadella",
)


class RemoteBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def reserve(self, maximum: int) -> None:
        if self.used + maximum > self.limit:
            raise RuntimeError(
                f"Remote-call ceiling would be exceeded: {self.used} used, {maximum} required, {self.limit} allowed."
            )

    def consume(self, actual: int) -> None:
        self.used += actual
        if self.used > self.limit:
            raise RuntimeError(f"Remote-call ceiling exceeded: {self.used} > {self.limit}.")


def parse_events(body: str) -> list[dict[str, Any]]:
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_results(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": "cloak-benchmark-results-2026-07-15.v1",
            "attacker": "gpt-5.6",
            "execution_remote_calls": 0,
            "cases": {},
        }
    payload = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    if payload.get("schema_version") != "cloak-benchmark-results-2026-07-15.v1":
        raise ValueError("Unsupported benchmark result cache schema.")
    validate_result_cache_models(payload)
    return payload


def aliases(case: BenchmarkCase) -> list[str]:
    return [case.protected_subject.canonical_identity, *case.protected_subject.aliases]


def score_attack(result: AttackResult, case: BenchmarkCase) -> dict[str, Any]:
    rank = identity_rank([item.identity for item in result.hypotheses], aliases(case))
    subject_evidence: list[str] = []
    if rank is not None:
        subject_evidence = result.hypotheses[rank - 1].evidence_quotes
    return {
        "status": "ok",
        "reidentified": rank is not None,
        "rank": rank,
        "top_guess": result.hypotheses[0].identity if result.hypotheses else None,
        "subject_evidence_quotes": subject_evidence,
        "returned_models": [result.returned_model],
        "latency_ms": result.latency_ms,
        "calls": 1,
    }


def run_static_condition(
    client: httpx.Client,
    case: BenchmarkCase,
    condition: Literal["raw", "direct_identifier_only"],
) -> dict[str, Any]:
    response = client.post(f"/api/benchmark-smoke/{case.case_id}/{condition}", json={})
    response.raise_for_status()
    payload = BenchmarkAttackResponse.model_validate(response.json())
    scored = score_attack(payload.attack, case)
    scored.update(
        {
            "candidate_sha256": payload.candidate_sha256,
            "detected_direct_identifiers": payload.detected_direct_identifiers,
            "detected_entity_types": payload.detected_entity_types,
        }
    )
    return scored


def _event_attack(event: dict[str, Any]) -> AttackResult | None:
    payload = event.get("attack")
    return AttackResult.model_validate(payload) if isinstance(payload, dict) else None


def run_cloak_condition(client: httpx.Client, case: BenchmarkCase) -> dict[str, Any]:
    created = client.post("/api/sessions", json={"text": case.document})
    created.raise_for_status()
    session_id = created.json()["session_id"]
    try:
        confirmed = client.post(
            f"/api/sessions/{session_id}/confirm",
            json={
                "subject": case.protected_subject.model_dump(mode="json"),
                "identifiers": case.direct_identifiers,
                "pins": case.utility_pins,
            },
        )
        confirmed.raise_for_status()
        initial = confirmed.json()["candidate"]
        leaked = [value for value in aliases(case) + case.direct_identifiers if value in initial["text"]]
        if leaked:
            raise RuntimeError(f"Full-loop initial candidate leaked confirmed direct values: {leaked!r}")

        run = client.post(f"/api/sessions/{session_id}/runs")
        run.raise_for_status()
        events = parse_events(run.text)
        if not events:
            raise RuntimeError("Full loop returned no trace events.")
        final = events[-1]
        candidate = final.get("candidate")
        if not isinstance(candidate, dict) or not isinstance(candidate.get("sha256"), str):
            raise RuntimeError("Full loop final event omitted its candidate hash.")
        final_hash = candidate["sha256"]
        final_attacks: list[AttackResult] = []
        all_attacks: list[AttackResult] = []
        for event in events:
            attack = _event_attack(event)
            if attack is None:
                continue
            all_attacks.append(attack)
            event_candidate = event.get("candidate")
            if isinstance(event_candidate, dict) and event_candidate.get("sha256") == final_hash:
                final_attacks.append(attack)
        if not final_attacks:
            raise RuntimeError("No GPT-5.6 result scored the full loop's final candidate.")
        ranks = [
            identity_rank([item.identity for item in attack.hypotheses], aliases(case)) for attack in final_attacks
        ]
        recovered_ranks = [rank for rank in ranks if rank is not None]
        best_rank = min(recovered_ranks) if recovered_ranks else None
        last_attack = final_attacks[-1]
        subject_evidence: list[str] = []
        if best_rank is not None:
            matching = next(attack for attack, rank in zip(final_attacks, ranks, strict=True) if rank == best_rank)
            subject_evidence = matching.hypotheses[best_rank - 1].evidence_quotes
        calls = max(int(event.get("calls_used", 0)) for event in events)
        return {
            "status": "ok",
            "reidentified": best_rank is not None,
            "rank": best_rank,
            "top_guess": last_attack.hypotheses[0].identity if last_attack.hypotheses else None,
            "subject_evidence_quotes": subject_evidence,
            "returned_models": sorted({attack.returned_model for attack in all_attacks}),
            "latency_ms": sum(attack.latency_ms for attack in all_attacks),
            "calls": calls,
            "edits": sum(event.get("phase") == "patch_accepted" for event in events),
            "final_phase": final.get("phase"),
            "final_title": final.get("title"),
            "verified": final.get("phase") == "run_passed",
            "candidate_sha256": final_hash,
            "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
            "trace_events": events,
        }
    finally:
        client.delete(f"/api/sessions/{session_id}")


def wilson_interval(reidentified: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    proportion = reidentified / total
    denominator = 1 + z**2 / total
    center = (proportion + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / total + z**2 / (4 * total**2)) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _condition_cell(result: dict[str, Any] | None) -> str:
    if not result or result.get("status") != "ok":
        return "not run"
    if result["reidentified"]:
        return f"yes · rank {result['rank']}"
    return "no"


def _rate_row(label: str, results: list[dict[str, Any]]) -> tuple[str, float]:
    scored = [result for result in results if result.get("status") == "ok"]
    recovered = sum(bool(result["reidentified"]) for result in scored)
    rate = recovered / len(scored) if scored else 0.0
    low, high = wilson_interval(recovered, len(scored))
    row = f"| {label} | {recovered}/{len(scored)} | {rate:.0%} | {low:.0%}–{high:.0%} | +{rate * 100:.1f} pp |"
    return row, rate


def write_report(path: Path, cases: list[BenchmarkCase], results: dict[str, Any]) -> None:
    case_results: dict[str, Any] = results["cases"]
    complete = all(
        case.case_id in case_results
        and all(
            condition_cache_is_current(
                condition,
                case_results[case.case_id].get("conditions", {}).get(condition),
            )
            for condition in CONDITIONS
        )
        for case in cases
    )
    condition_results = {
        condition: [case_results.get(case.case_id, {}).get("conditions", {}).get(condition, {}) for case in cases]
        for condition in CONDITIONS
    }
    rows: list[str] = []
    rates: dict[str, float] = {}
    for condition, label in CONDITION_LABELS:
        row, rate = _rate_row(label, condition_results[condition])
        rows.append(row)
        rates[condition] = rate

    qualified = sum(
        case_results.get(case.case_id, {}).get("conditions", {}).get("raw", {}).get("reidentified") is True
        for case in cases
    )
    represented_calls = sum(
        int(condition.get("calls", 0))
        for case in case_results.values()
        for condition in case.get("conditions", {}).values()
    )
    execution_calls = int(results.get("execution_remote_calls", represented_calls))
    returned_models = sorted(
        {
            model
            for case in case_results.values()
            for condition in case.get("conditions", {}).values()
            for model in condition.get("returned_models", [])
        }
    )
    headline = (
        f"raw {rates['raw']:.0%} → naive redaction {rates['direct_identifier_only']:.0%} "
        f"→ Admissible {rates['cloak']:.0%}"
    )
    lines = [
        "# Admissible benchmark smoke set",
        "",
        f"- Date: {datetime.now().astimezone().date().isoformat()}",
        f"- Status: **{'complete' if complete else 'partial'} reported smoke set**",
        f"- Headline: **{headline}**",
        f"- Sample: {len(cases)} English synthetic cases; {qualified}/{len(cases)} raw-identifiable",
        f"- Attacker: fixed cross-family GPT-5.6 adapter; returned models: {', '.join(returned_models) or 'not run'}",
        f"- Final-condition remote calls represented: {represented_calls}",
        f"- Total execution calls, including superseded fixture revisions: {execution_calls}",
        "",
        (
            "This is a deliberately small, author-generated smoke set—not a validated benchmark, release bar, or "
            "demo blocker. The aspirational target is a near-zero final re-identification rate; the table reports "
            "the observed point gap to 0% and a 95% Wilson interval so a small sample cannot masquerade as validation."
        ),
        "",
        "## Overall result",
        "",
        "| Condition | Re-identified | Rate | 95% Wilson interval | Gap to 0% aspiration |",
        "|---|---:|---:|---:|---:|",
        *rows,
        "",
        (
            f"Against the naive baseline, Admissible changed the observed rate by "
            f"{(rates['cloak'] - rates['direct_identifier_only']) * 100:+.1f} percentage points. "
            "This sample is too small to treat that difference as validated."
        ),
        "",
        (
            "Raw and naive conditions use one medium-effort attack each. Admissible uses the production core loop: "
            "medium-effort discovery/post-edit attacks. The stack-aware controller can retire up to two grounded "
            "clues per attack and seven total edits, then "
            "requires a separate high-effort holdout. Causal deepening is disabled."
        ),
        "",
        "## Same-case controller change",
        "",
        (
            "The pre-fix run on these exact fixtures and the same GPT-5.6 attacker was **raw 100% → naive 60% → "
            "Admissible 53% (8/15)**. The stack-aware controller reduced Admissible to **33% (5/15)**, a 20-point "
            "improvement. Single-clue re-identification fell from 3/5 to 1/5; aggregate re-identification fell "
            "from 5/5 to 4/5. Direct-PII controls remained 0/5."
        ),
        "",
        (
            "This is still a failed near-zero aspiration, especially for aggregate cases. The one aggregate pass "
            "shows that the controller can exhaust a removable clue stack. Each of the four residual aggregate "
            "cases has a must-preserve sentence that itself describes the subject's distinctive arc; Admissible blocks "
            "instead of deleting that pinned substance or claiming a pass."
        ),
        "",
        "## Breakdown by difficulty",
        "",
        "| Difficulty | Condition | Re-identified | Rate |",
        "|---|---|---:|---:|",
    ]
    labels = {
        "direct_pii": "Direct-PII control",
        "single_distinctive_clue": "Single distinctive clue",
        "aggregate_quasi_identifiers": "Aggregate quasi-identifiers",
    }
    for difficulty, difficulty_label in labels.items():
        matching = [case for case in cases if case.difficulty == difficulty]
        for condition, condition_label in (
            ("raw", "Raw"),
            ("direct_identifier_only", "Naive"),
            ("cloak", "Admissible"),
        ):
            scored = [case_results.get(case.case_id, {}).get("conditions", {}).get(condition, {}) for case in matching]
            scored = [result for result in scored if result.get("status") == "ok"]
            recovered = sum(bool(result["reidentified"]) for result in scored)
            rate = recovered / len(scored) if scored else 0.0
            lines.append(f"| {difficulty_label} | {condition_label} | {recovered}/{len(scored)} | {rate:.0%} |")

    lines.extend(
        [
            "",
            "## Per-case outcomes",
            "",
            (
                "| Case | Protected subject | Difficulty | Raw | Naive | Admissible | Full-loop outcome | Calls | "
                "Substance-bound |"
            ),
            "|---|---|---|---|---|---|---|---:|---|",
        ]
    )
    for case in cases:
        conditions = case_results.get(case.case_id, {}).get("conditions", {})
        admissible = conditions.get("cloak", {})
        case_calls = sum(int(item.get("calls", 0)) for item in conditions.values())
        lines.append(
            f"| `{case.case_id}` | {case.protected_subject.canonical_identity} | {labels[case.difficulty]} | "
            f"{_condition_cell(conditions.get('raw'))} | {_condition_cell(conditions.get('direct_identifier_only'))} | "
            f"{_condition_cell(admissible)} | {admissible.get('final_phase', 'not run')} | {case_calls} | "
            f"{'yes' if case.identity_is_substance else 'no'} |"
        )

    residuals = [
        (case, case_results.get(case.case_id, {}).get("conditions", {}).get("cloak", {}))
        for case in cases
        if case_results.get(case.case_id, {}).get("conditions", {}).get("cloak", {}).get("reidentified") is True
    ]
    lines.extend(["", "## Residual Admissible re-identifications", ""])
    if residuals:
        for case, result in residuals:
            evidence = result.get("subject_evidence_quotes") or []
            evidence_note = f" Evidence: {evidence!r}." if evidence else ""
            lines.append(
                f"- `{case.case_id}`: rank {result.get('rank')}, {result.get('final_phase')}, "
                f"{result.get('edits', 0)} accepted edits.{evidence_note}"
            )
    else:
        lines.append(
            "- None in this smoke set. The Wilson upper bound still prevents a population-level near-zero claim."
        )

    lines.extend(["", "## Aggregate core-loop traces", ""])
    for case in cases:
        if case.difficulty != "aggregate_quasi_identifiers":
            continue
        result = case_results.get(case.case_id, {}).get("conditions", {}).get("cloak", {})
        trace = result.get("trace_events", [])
        patches = [event.get("patch") for event in trace if event.get("phase") == "patch_accepted"]
        patch_text = "; ".join(
            f"`{patch.get('old_text', '')}` → `{patch.get('replacement', '')}`"
            for patch in patches
            if isinstance(patch, dict)
        )
        residual = result.get("subject_evidence_quotes") or []
        final_candidate = trace[-1].get("candidate", {}) if trace else {}
        cumulative = final_candidate.get("cumulative_edit_ratio") if isinstance(final_candidate, dict) else None
        cumulative_text = f"{float(cumulative):.1%}" if isinstance(cumulative, int | float) else "unknown"
        lines.append(
            f"- `{case.case_id}`: {len(patches)} accepted edits; final `{result.get('final_phase', 'not run')}` "
            f"({result.get('final_title', 'not run')}); cumulative edit distance {cumulative_text}. "
            f"Patches: {patch_text or 'none'}. Residual subject evidence: {residual!r}."
        )

    lines.extend(["", "## Identity-is-substance flags", ""])
    for case in cases:
        if case.identity_is_substance:
            lines.append(f"- `{case.case_id}`: {case.substance_note}")

    lines.extend(
        [
            "",
            "## Interpretation and limits",
            "",
            (
                "- Cases were authored from scratch inside the Admissible repository; no external dataset "
                "or repository was imported."
            ),
            (
                "- The raw condition sends only these committed synthetic fixtures through a case-ID-only loopback "
                "route whose strict empty control body rejects document text. It is not a path for user documents "
                "and does not weaken Admissible's product boundary."
            ),
            (
                "- Every full-set case had to be recovered from its raw document before its baselines were scored. "
                "A raw miss halts the runner rather than making later conditions look artificially safe."
            ),
            (
                "- The naive baseline uses Presidio `PatternRecognizer` rules for direct contact/number spans plus "
                "Admissible's confirmed subject aliases, then replaces those exact values with local opaque tokens. "
                "It performs no inference."
            ),
            (
                "- This is one English set, one run per condition, one attacker family, and no independent human "
                "utility rating. Prompt stochasticity and public-knowledge changes are not estimated."
            ),
            (
                "- A 0% point estimate would not validate anonymity: with only 15 cases, its 95% Wilson upper bound "
                "remains material. Conversely, any residual case is a concrete controller/product finding, not a "
                "release-gate failure."
            ),
            (
                "- Several profiles intentionally make identity the substance. Their flags distinguish privacy "
                "failure from the harder reality that removing the identifying story may destroy the document's "
                "purpose."
            ),
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def select_cases(mode: str, case_ids: list[str]) -> list[BenchmarkCase]:
    corpus = load_benchmark_corpus()
    selected_ids = case_ids or (list(SANITY_CASE_IDS) if mode == "sanity" else [])
    if not selected_ids:
        return corpus.cases
    by_id = {case.case_id: case for case in corpus.cases}
    missing = [case_id for case_id in selected_ids if case_id not in by_id]
    if missing:
        raise ValueError(f"Unknown benchmark case IDs: {missing}")
    return [by_id[case_id] for case_id in selected_ids]


def condition_cache_is_current(condition: Condition, result: object) -> bool:
    if not isinstance(result, dict) or result.get("status") != "ok":
        return False
    if condition != "cloak":
        return True
    return result.get("controller_protocol_version") == CONTROLLER_PROTOCOL_VERSION


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Admissible's bounded synthetic re-identification smoke set.")
    parser.add_argument("mode", choices=("sanity", "full"))
    parser.add_argument("--case-id", action="append", default=[], dest="case_ids")
    parser.add_argument("--max-new-remote-calls", type=int, default=24)
    parser.add_argument("--rerun-admissible", action="store_true")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    corpus = load_benchmark_corpus()
    selected = select_cases(args.mode, args.case_ids)
    results = load_results(args.results)
    budget = RemoteBudget(args.max_new_remote_calls)
    cache_complete = not args.rerun_cloak and all(
        isinstance(results["cases"].get(case.case_id), dict)
        and results["cases"][case.case_id].get("case_fingerprint") == corpus_fingerprint(case)
        and all(
            condition_cache_is_current(
                condition,
                results["cases"][case.case_id].get("conditions", {}).get(condition),
            )
            for condition in CONDITIONS
        )
        for case in selected
    )
    if cache_complete:
        write_report(args.report, corpus.cases, results)
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "selected_cases": len(selected),
                    "new_remote_calls": 0,
                    "results": str(args.results),
                    "report": str(args.report),
                }
            )
        )
        return 0

    with httpx.Client(base_url=BASE_URL, timeout=240.0) as client:
        health = client.get("/api/health")
        health.raise_for_status()
        health_payload = health.json()
        if not health_payload.get("attacker_ready") or not health_payload.get("ollama_ready"):
            raise RuntimeError("The local GPT-5.6 attacker and Ollama anonymizer must both be ready.")

        for case in selected:
            fingerprint = corpus_fingerprint(case)
            case_cache = results["cases"].get(case.case_id)
            if not isinstance(case_cache, dict) or case_cache.get("case_fingerprint") != fingerprint:
                case_cache = {
                    "case_fingerprint": fingerprint,
                    "difficulty": case.difficulty,
                    "protected_subject": case.protected_subject.canonical_identity,
                    "identity_is_substance": case.identity_is_substance,
                    "conditions": {},
                }
                results["cases"][case.case_id] = case_cache
            conditions: dict[str, Any] = case_cache["conditions"]
            for condition in CONDITIONS:
                force_cloak = args.rerun_cloak and condition == "cloak"
                if condition_cache_is_current(condition, conditions.get(condition)) and not force_cloak:
                    continue
                maximum = 8 if condition == "cloak" else 1
                budget.reserve(maximum)
                if condition == "cloak":
                    outcome = run_cloak_condition(client, case)
                else:
                    outcome = run_static_condition(client, case, condition)
                budget.consume(int(outcome["calls"]))
                results["execution_remote_calls"] = int(results.get("execution_remote_calls", 0)) + int(
                    outcome["calls"]
                )
                conditions[condition] = outcome
                results["updated_at"] = datetime.now(UTC).isoformat()
                results["last_mode"] = args.mode
                atomic_write_json(args.results, results)
                print(
                    json.dumps(
                        {
                            "case": case.case_id,
                            "condition": condition,
                            "reidentified": outcome["reidentified"],
                            "rank": outcome["rank"],
                            "phase": outcome.get("final_phase"),
                            "calls": outcome["calls"],
                            "new_calls_used": budget.used,
                        }
                    ),
                    flush=True,
                )
                if condition == "raw" and not outcome["reidentified"]:
                    write_report(args.report, corpus.cases, results)
                    raise RuntimeError(
                        f"{case.case_id} failed raw identifiability. Regenerate that case before scoring baselines."
                    )

    write_report(args.report, corpus.cases, results)
    print(
        json.dumps(
            {
                "mode": args.mode,
                "selected_cases": len(selected),
                "new_remote_calls": budget.used,
                "results": str(args.results),
                "report": str(args.report),
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        print(f"benchmark stopped: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
