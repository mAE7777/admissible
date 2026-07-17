from __future__ import annotations

from cloak.models import (
    AttackResult,
    GroundedEvidence,
    IdentityHypothesis,
    PatchProposal,
    TraceEvent,
    UtilityLedger,
)
from cloak.privacy import candidate_from_text

DEMO_SURROGATE = "Jamie Ives"
DEMO_INITIAL = (
    f"{DEMO_SURROGATE} led the Harborlight reporting project. The subject won the 2019 Northshore "
    "Civic Data Prize and later taught the Tuesday night newsroom lab at Westbridge College."
)
DEMO_CLUE = "2019 Northshore Civic Data Prize"
DEMO_REPLACEMENT = "regional civic data award"
DEMO_FINAL = DEMO_INITIAL.replace(DEMO_CLUE, DEMO_REPLACEMENT)

REFUSAL_SURROGATE = "Jordan Vale"
REFUSAL_SUBJECT = "Elena Marrow"
REFUSAL_CLUE = (
    "the only pediatric perfusionist at Redvale Community Hospital who survived the 2023 Halden footbridge "
    "collapse and returned to work on 8 January 2024"
)
REFUSAL_DOCUMENT = (
    f"{REFUSAL_SURROGATE} is {REFUSAL_CLUE}. Their accommodation request asks to retain a 24-hour schedule. "
    "Review whether the role, event, return date, and reduced schedule support the workplace accommodation request."
)


def _harbor_demo() -> dict[str, object]:
    initial = candidate_from_text(DEMO_INITIAL, original_text=DEMO_INITIAL, pass_number=0, parent_sha256=None)
    final = candidate_from_text(
        DEMO_FINAL,
        original_text=DEMO_INITIAL,
        pass_number=1,
        parent_sha256=initial.sha256,
        previous_text=DEMO_INITIAL,
    )
    attack = AttackResult(
        returned_model="gpt-5.6-sol (recorded)",
        hypotheses=[
            IdentityHypothesis(
                identity="Mara Voss",
                confidence=0.84,
                evidence_quotes=[DEMO_CLUE],
            ),
            IdentityHypothesis(identity="Elena Park", confidence=0.21, evidence_quotes=[]),
        ],
        latency_ms=3260,
        usage={"total_tokens": 642},
    )
    miss = AttackResult(
        returned_model="gpt-5.6-sol (recorded)",
        hypotheses=[IdentityHypothesis(identity="Unable to identify", confidence=0.08, evidence_quotes=[])],
        latency_ms=2810,
        usage={"total_tokens": 511},
    )
    clue_start = DEMO_INITIAL.index(DEMO_CLUE)
    evidence = GroundedEvidence(
        quote=DEMO_CLUE,
        status="grounded",
        codepoint_start=clue_start,
        codepoint_end=clue_start + len(DEMO_CLUE),
        utf16_start=clue_start,
        utf16_end=clue_start + len(DEMO_CLUE),
    )
    patch = PatchProposal(
        old_text=DEMO_CLUE,
        replacement=DEMO_REPLACEMENT,
        rationale="Keeps the accomplishment while removing the unique award and year.",
    )
    utility = UtilityLedger(
        accepted=True,
        reasons=["Surrogates, pins, edit scope, and utility budget are intact."],
        tokens_intact=True,
        pins_intact=True,
        authorized_span_only=True,
        per_pass_edit_ratio=final.per_pass_edit_ratio,
        cumulative_edit_ratio=final.cumulative_edit_ratio,
    )
    raw_events = [
        TraceEvent(
            event_id="recorded:1",
            mode="recorded",
            phase="attack_result",
            title="GPT-5.6 found the subject",
            detail="Mara Voss appeared at rank 1.",
            status="blocked",
            attack=attack,
            candidate=initial,
            calls_used=1,
        ),
        TraceEvent(
            event_id="recorded:2",
            mode="recorded",
            phase="evidence_grounding",
            title="The clue maps to one exact span",
            detail="The quote exists once; the controller allows a minimal edit.",
            status="passed",
            evidence=[evidence],
            candidate=initial,
            calls_used=1,
        ),
        TraceEvent(
            event_id="recorded:3",
            mode="recorded",
            phase="patch_accepted",
            title="Only the identifying clue changed",
            detail="The award remains useful, while its unique name and year are generalized.",
            status="changed",
            evidence=[evidence],
            patch=patch,
            utility=utility,
            candidate=final,
            calls_used=1,
        ),
        TraceEvent(
            event_id="recorded:4",
            mode="recorded",
            phase="holdout",
            title="Discovery and holdout both miss",
            detail="The protected subject is absent from both top-five lists.",
            status="passed",
            attack=miss,
            candidate=final,
            calls_used=3,
        ),
        TraceEvent(
            event_id="recorded:5",
            mode="recorded",
            phase="run_passed",
            title="This attacker could no longer identify the subject",
            detail=(
                "Discovery and holdout omitted the protected subject. This cached synthetic trace does not test "
                "attackers holding external records."
            ),
            status="passed",
            candidate=final,
            calls_used=3,
        ),
    ]
    return {
        "slug": "harbor",
        "label": "Recorded · synthetic",
        "protected_subject": "Mara Voss",
        "events": [event.model_dump(mode="json") for event in raw_events],
    }


def _task_conflict_demo() -> dict[str, object]:
    candidate = candidate_from_text(
        REFUSAL_DOCUMENT,
        original_text=REFUSAL_DOCUMENT,
        pass_number=0,
        parent_sha256=None,
    )
    clue_start = REFUSAL_DOCUMENT.index(REFUSAL_CLUE)
    evidence = GroundedEvidence(
        quote=REFUSAL_CLUE,
        status="grounded",
        codepoint_start=clue_start,
        codepoint_end=clue_start + len(REFUSAL_CLUE),
        utf16_start=clue_start,
        utf16_end=clue_start + len(REFUSAL_CLUE),
    )
    attack = AttackResult(
        returned_model="gpt-5.6-sol (recorded)",
        hypotheses=[
            IdentityHypothesis(
                identity=REFUSAL_SUBJECT,
                confidence=0.93,
                evidence_quotes=[REFUSAL_CLUE],
            ),
            IdentityHypothesis(identity="Morgan Ellis", confidence=0.18, evidence_quotes=[]),
        ],
        latency_ms=3480,
        usage={"total_tokens": 704},
    )
    events = [
        TraceEvent(
            event_id="task-conflict:1",
            mode="recorded",
            phase="attack_result",
            title="GPT-5.6 linked the subject",
            detail=(
                "In this recorded synthetic stress case, Elena Marrow appeared at rank 1 after the distinctive "
                "role, event, and return date were linked."
            ),
            status="blocked",
            attack=attack,
            candidate=candidate,
            calls_used=1,
        ),
        TraceEvent(
            event_id="task-conflict:2",
            mode="recorded",
            phase="evidence_grounding",
            title="The identifying stack maps to one exact span",
            detail="The attacker's quote exists once in the tested text.",
            status="passed",
            evidence=[evidence],
            candidate=candidate,
            calls_used=1,
        ),
        TraceEvent(
            event_id="task-conflict:3",
            mode="recorded",
            phase="patch_rejected",
            title="The task needs the same facts",
            detail=(
                "Removing the role, event, or return date would make the requested accommodation review materially "
                "wrong, so Cloak left the sentence unchanged."
            ),
            status="info",
            evidence=[evidence],
            candidate=candidate,
            conflicting_facts=[REFUSAL_CLUE],
            calls_used=1,
        ),
        TraceEvent(
            event_id="task-conflict:4",
            mode="recorded",
            phase="run_blocked",
            title="Cloak refused to fake privacy",
            detail=(
                "The exact identifying facts are also required for the downstream task. The candidate remains "
                "unchanged and is not cleared to share."
            ),
            status="blocked",
            candidate=candidate,
            conflicting_facts=[REFUSAL_CLUE],
            calls_used=1,
        ),
    ]
    return {
        "slug": "task-conflict",
        "label": "Recorded · synthetic task conflict",
        "protected_subject": REFUSAL_SUBJECT,
        "events": [event.model_dump(mode="json") for event in events],
    }


def recorded_demo(slug: str = "harbor") -> dict[str, object]:
    if slug == "harbor":
        return _harbor_demo()
    if slug == "task-conflict":
        return _task_conflict_demo()
    raise KeyError(slug)
