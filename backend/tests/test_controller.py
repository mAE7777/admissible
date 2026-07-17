from __future__ import annotations

from collections.abc import Iterable

import pytest

from cloak.controller import Controller, parse_sse_payload
from cloak.models import (
    AttackResult,
    ConfirmSessionRequest,
    IdentityHypothesis,
    PatchProposal,
    ProtectedSubject,
    SanitizedEnvelope,
)
from cloak.sessions import SessionStore

DOCUMENT = (
    "Mara Voss led the Harborlight reporting project for a regional newsroom with a small team. "
    "The subject won the 2019 Northshore Civic Data Prize after a year of public records work. "
    "Later, the subject taught a recurring newsroom lab and published a practical field guide. "
    "Contact mara.voss@example.com for the archived materials and publication notes."
)
CLUE = "Northshore Civic Data Prize"


def attack(*hypotheses: IdentityHypothesis) -> AttackResult:
    return AttackResult(
        returned_model="gpt-5.6-sol-2026-07-01",
        hypotheses=list(hypotheses),
        latency_ms=100,
    )


class FakeAttacker:
    def __init__(self, results: Iterable[AttackResult]) -> None:
        self.results = iter(results)
        self.envelopes: list[SanitizedEnvelope] = []

    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult:
        self.envelopes.append(envelope)
        return next(self.results)


class FakeAnonymizer:
    def __init__(
        self,
        replacement: str = "regional civic data award",
        replacements: dict[str, str] | None = None,
        task_facts: list[str] | None = None,
        tokenize_values: list[str] | None = None,
    ) -> None:
        self.replacement = replacement
        self.replacements = replacements or {}
        self.task_facts = task_facts or []
        self.tokenize_values = tokenize_values or []
        self.calls = 0
        self.prior_replacements: list[str | None] = []

    async def ready(self) -> bool:
        return True

    async def plan_task_facts(self, candidate: str, task: str) -> list[str]:
        del candidate, task
        return self.task_facts

    async def propose_patch(
        self,
        candidate: str,
        evidence_quote: str,
        prior_replacement: str | None = None,
        task: str = "",
        protected_facts: list[str] | None = None,
    ) -> PatchProposal:
        del task, protected_facts
        self.calls += 1
        self.prior_replacements.append(prior_replacement)
        old_text = prior_replacement or evidence_quote
        replacement = (
            "broad professional fact"
            if prior_replacement is not None
            else self.replacements.get(evidence_quote, self.replacement)
        )
        return PatchProposal(
            old_text=old_text,
            replacement=replacement,
            rationale="Remove the unique award and year while keeping the achievement.",
            tokenize_values=self.tokenize_values,
        )


def confirmed_session(
    task: str = "Preserve the document's substantive reporting history while hiding the subject.",
    pins: list[str] | None = None,
):
    store = SessionStore()
    draft = store.create(DOCUMENT)
    store.confirm(
        draft.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Mara Voss", aliases=["Voss"]),
            identifiers=["mara.voss@example.com"],
            pins=pins or ["public records work"],
            task=task,
        ),
    )
    return store.get(draft.session_id)


async def collect(controller: Controller, session) -> list[dict[str, object]]:
    chunks = [chunk async for chunk in controller.run(session)]
    return parse_sse_payload("".join(chunks))


@pytest.mark.asyncio
async def test_working_loop_guess_ground_patch_miss_holdout_restore() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.16)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
        ]
    )
    anonymizer = FakeAnonymizer()
    session = confirmed_session()
    events = await collect(Controller(attacker, anonymizer), session)
    phases = [event["phase"] for event in events]
    assert phases == [
        "run_started",
        "utility_profile",
        "attacking",
        "attack_result",
        "evidence_grounding",
        "patch_accepted",
        "attacking",
        "attack_result",
        "guess_rejected",
        "holdout",
        "run_passed",
    ]
    assert events[-1]["title"] == "This attacker could no longer identify the subject"
    assert all(event["prompt_version"] == "cloak-attacker-2026-07-16.v2" for event in events)
    assert all(event["schema_version"] == "cloak-trace-2026-07-15.v1" for event in events)
    assert all(event["model_version"] == "gpt-5.6" for event in events)
    assert anonymizer.calls == 1
    assert len(attacker.envelopes) == 3
    assert all("Mara Voss" not in item.candidate_text for item in attacker.envelopes)
    assert all("mara.voss@example.com" not in item.candidate_text for item in attacker.envelopes)
    assert all("substantive reporting history" not in item.candidate_text for item in attacker.envelopes)
    assert session.candidate is not None
    assert "regional civic data award" in session.candidate.text
    restored = session.vault.restore(session.candidate.text)
    assert "Mara Voss" in restored.restored_text
    assert "mara.voss@example.com" in restored.restored_text


@pytest.mark.asyncio
async def test_task_critical_fact_loss_blocks_and_names_the_exact_conflict() -> None:
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE]))]
    )
    anonymizer = FakeAnonymizer()
    session = confirmed_session(
        "Build a chronology and preserve the exact dates while hiding the subject.",
        pins=[CLUE],
    )
    events = await collect(Controller(attacker, anonymizer), session)
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert events[-1]["conflicting_facts"][0] == CLUE
    assert len(attacker.envelopes) == 1


@pytest.mark.asyncio
async def test_exact_role_task_blocks_instead_of_verifying_role_loss() -> None:
    document = (
        "Jordan Okafor served as trustee for the pension plan. "
        "The plan covers several hundred employees across multiple locations. "
        "This memorandum summarizes administrative history, routine governance, reporting procedures, meeting "
        "cadence, record retention practices, and ordinary operational context for the review."
    )
    store = SessionStore()
    created = store.create(document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Jordan Okafor"),
            task="Identify each person's exact role and fiduciary obligations.",
        ),
    )
    session = store.get(created.session_id)
    clue = "served as trustee for the pension plan"
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Jordan Okafor", confidence=0.95, evidence_quotes=[clue]))]
    )
    events = await collect(
        Controller(
            attacker,
            FakeAnonymizer(replacement="handled responsibilities for the pension plan"),
        ),
        session,
    )
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert clue in events[-1]["conflicting_facts"]
    assert session.candidate is not None and "trustee" in session.candidate.text
    assert len(attacker.envelopes) == 1


@pytest.mark.asyncio
async def test_event_direction_task_blocks_instead_of_verifying_reversal() -> None:
    document = (
        "Mara Voss prepared a long internal operations record for archival review. "
        "The board terminated Dana Reed after an audit exposed missing records. "
        "The remaining file contains routine background, meeting logistics, document-retention notes, and neutral "
        "context so a surgical sentence edit remains inside the utility budget."
    )
    store = SessionStore()
    created = store.create(document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Mara Voss"),
            identifiers=["Dana Reed"],
            task="Explain who terminated whom and why.",
        ),
    )
    session = store.get(created.session_id)
    token = next(token for token, value in session.vault.token_to_value.items() if value == "Dana Reed")
    clue = f"The board terminated {token} after an audit exposed missing records."
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Mara Voss", confidence=0.9, evidence_quotes=[clue]))]
    )
    events = await collect(
        Controller(attacker, FakeAnonymizer(replacement=f"{token} terminated the board after a review of records.")),
        session,
    )
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert clue in events[-1]["conflicting_facts"]
    assert session.candidate is not None
    assert "The board terminated" in session.candidate.text


@pytest.mark.asyncio
async def test_event_polarity_task_blocks_instead_of_verifying_opposite_action() -> None:
    document = (
        "Jordan Okafor noted that the manager promoted the employee to lead the project. "
        "The file also contains routine background, meeting logistics, retention notes, and several paragraphs of "
        "neutral administrative context so a surgical edit remains inside the utility budget."
    )
    store = SessionStore()
    created = store.create(document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Jordan Okafor"),
            task="Determine whether the manager promoted or demoted the employee.",
        ),
    )
    session = store.get(created.session_id)
    clue = "the manager promoted the employee to lead the project"
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Jordan Okafor", confidence=0.9, evidence_quotes=[clue]))]
    )
    events = await collect(
        Controller(attacker, FakeAnonymizer(replacement="manager demoted the employee from the project")),
        session,
    )
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert clue in events[-1]["conflicting_facts"]
    assert session.candidate is not None
    assert "promoted" in session.candidate.text and "demoted" not in session.candidate.text


@pytest.mark.asyncio
async def test_identifying_specific_can_become_a_restorable_token_without_losing_task_fact() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.16)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
        ]
    )
    anonymizer = FakeAnonymizer(
        replacement=CLUE,
        task_facts=["2019"],
        tokenize_values=["Northshore"],
    )
    session = confirmed_session()
    events = await collect(Controller(attacker, anonymizer), session)
    assert events[-1]["phase"] == "run_passed"
    assert session.candidate is not None
    assert "Northshore" not in session.candidate.text
    assert "2019" in session.candidate.text
    restored = session.vault.restore(session.candidate.text)
    assert CLUE in restored.restored_text


@pytest.mark.asyncio
async def test_privacy_regression_rolls_back_staged_entity_tokens_with_the_candidate() -> None:
    attacker = FakeAttacker(
        [
            attack(
                IdentityHypothesis(identity="Someone else", confidence=0.95),
                IdentityHypothesis(identity="Mara Voss", confidence=0.82, evidence_quotes=[CLUE]),
            ),
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.97)),
        ]
    )
    anonymizer = FakeAnonymizer(replacement=CLUE, tokenize_values=["Northshore"])
    session = confirmed_session()
    original_tokens = set(session.vault.token_to_value)
    events = await collect(Controller(attacker, anonymizer), session)
    assert events[-1]["title"] == "The edit made re-identification easier"
    assert session.candidate is not None and CLUE in session.candidate.text
    assert set(session.vault.token_to_value) == original_tokens


@pytest.mark.asyncio
async def test_financial_task_blocks_before_removing_a_task_critical_transaction() -> None:
    document = (
        "Cardholder: Evelyn Brooks. Credit limit: $8,000.00. "
        "14 Jun — Laurent Hotel, Montreal — $612.00. "
        "The statement also lists ordinary groceries, utilities, interest, the minimum payment, and the due date. "
        "The requested review should reconcile every listed transaction and explain the next billing-cycle risks."
    )
    store = SessionStore()
    created = store.create(document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Evelyn Brooks"),
            task="Review fees, utilization, payment risks, and unusual spending by date.",
        ),
    )
    session = store.get(created.session_id)
    attacker = FakeAttacker(
        [
            attack(
                IdentityHypothesis(
                    identity="Evelyn Brooks",
                    confidence=0.95,
                    evidence_quotes=[
                        "Credit limit: $8,000.00",
                        "14 Jun — Laurent Hotel, Montreal — $612.00",
                    ],
                )
            ),
            attack(
                IdentityHypothesis(
                    identity="Evelyn Brooks",
                    confidence=0.93,
                    evidence_quotes=["Credit limit: $8,000.00"],
                )
            ),
        ]
    )
    anonymizer = FakeAnonymizer()
    events = await collect(Controller(attacker, anonymizer), session)
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert anonymizer.calls == 0
    assert session.candidate is not None
    assert "$8,000.00" in session.candidate.text
    assert "14 Jun" in session.candidate.text
    assert "$612.00" in session.candidate.text
    assert "Hotel" in session.candidate.text
    assert "Laurent" in session.candidate.text
    assert "Montreal" in session.candidate.text
    assert "Credit limit: $8,000.00" in events[-1]["conflicting_facts"]


@pytest.mark.asyncio
async def test_hr_direct_statement_blocks_intact_instead_of_reversing_the_event() -> None:
    statement = (
        "On 12 February, my manager said during a planning meeting that the promotion panel needed someone whose "
        "commitment would not be divided by a new baby."
    )
    document = f"Complainant: Jordan Okafor. {statement}"
    store = SessionStore()
    created = store.create(document)
    store.confirm(
        created.session_id,
        ConfirmSessionRequest(
            subject=ProtectedSubject(canonical_identity="Jordan Okafor"),
            task="Build a chronology and separate direct evidence from inference with exact context.",
        ),
    )
    session = store.get(created.session_id)
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Jordan Okafor", confidence=0.95, evidence_quotes=[statement]))]
    )
    anonymizer = FakeAnonymizer()
    events = await collect(Controller(attacker, anonymizer), session)
    assert events[-1]["title"] == "Privacy and task utility conflict"
    assert statement in events[-1]["conflicting_facts"]
    assert anonymizer.calls == 0
    assert session.candidate is not None and statement in session.candidate.text


@pytest.mark.asyncio
async def test_wrong_identity_cannot_trigger_edit() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Elena Park", confidence=0.98, evidence_quotes=["invented quote"])),
            attack(IdentityHypothesis(identity="Elena Park", confidence=0.72)),
        ]
    )
    anonymizer = FakeAnonymizer()
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert anonymizer.calls == 0
    assert events[-1]["phase"] == "run_passed"
    assert "guess_rejected" in [event["phase"] for event in events]


@pytest.mark.asyncio
async def test_correct_identity_with_fabricated_quote_blocks_without_edit() -> None:
    attacker = FakeAttacker(
        [attack(IdentityHypothesis(identity="Mara Voss", confidence=0.94, evidence_quotes=["quote not in text"]))]
    )
    anonymizer = FakeAnonymizer()
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_blocked"
    assert "discarded" in str(events[-1]["title"]).lower()
    assert anonymizer.calls == 0


@pytest.mark.asyncio
async def test_utility_budget_rejects_mush_before_second_remote_call() -> None:
    attacker = FakeAttacker([attack(IdentityHypothesis(identity="Mara Voss", confidence=0.94, evidence_quotes=[CLUE]))])
    anonymizer = FakeAnonymizer(replacement="generic " * 200)
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_blocked"
    assert len(attacker.envelopes) == 1
    rejected = next(event for event in events if event["phase"] == "patch_rejected")
    assert rejected["utility"]["accepted"] is False  # type: ignore[index]


@pytest.mark.asyncio
async def test_privacy_regression_reverts_to_previous_best_candidate() -> None:
    attacker = FakeAttacker(
        [
            attack(
                IdentityHypothesis(identity="Someone else", confidence=0.95),
                IdentityHypothesis(identity="Mara Voss", confidence=0.82, evidence_quotes=[CLUE]),
            ),
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.97)),
        ]
    )
    session = confirmed_session()
    events = await collect(Controller(attacker, FakeAnonymizer("regional civic data award")), session)
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "The edit made re-identification easier"
    assert session.candidate is not None
    assert session.candidate.pass_number == 0
    assert CLUE in session.candidate.text
    assert "regional civic data award" not in session.candidate.text


@pytest.mark.asyncio
async def test_unchanged_rank_continues_through_fresh_grounded_clues() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(
                IdentityHypothesis(
                    identity="Mara Voss",
                    confidence=0.91,
                    evidence_quotes=["recurring newsroom lab"],
                )
            ),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.15)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
        ]
    )
    session = confirmed_session()
    events = await collect(Controller(attacker, FakeAnonymizer("regional civic data award")), session)
    assert events[-1]["phase"] == "run_passed"
    assert "rank_unchanged" in [event["phase"] for event in events]
    assert [event["phase"] for event in events].count("patch_accepted") == 2
    assert session.candidate is not None
    assert session.candidate.pass_number == 2
    assert CLUE not in session.candidate.text


@pytest.mark.asyncio
async def test_two_grounded_clues_are_batched_before_the_next_remote_attack() -> None:
    first = attack(
        IdentityHypothesis(
            identity="Mara Voss",
            confidence=0.91,
            evidence_quotes=[CLUE, "recurring newsroom lab"],
        )
    )
    attacker = FakeAttacker(
        [
            first,
            attack(IdentityHypothesis(identity="Someone else", confidence=0.16)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
        ]
    )
    anonymizer = FakeAnonymizer()
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_passed"
    assert len(attacker.envelopes) == 3
    assert anonymizer.calls == 2
    phases = [event["phase"] for event in events]
    second_attack = phases.index("attacking", phases.index("attacking") + 1)
    assert phases[:second_attack].count("patch_accepted") == 2


@pytest.mark.asyncio
async def test_seven_edit_cap_blocks_only_after_testing_the_seventh_edit() -> None:
    clue_batches = [
        [CLUE, "regional newsroom"],
        ["small team", "recurring newsroom lab"],
        ["practical field guide", "archived materials"],
        ["publication notes"],
        ["Harborlight reporting project"],
    ]
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=quotes))
            for quotes in clue_batches
        ]
    )
    replacements = {quote: "broader detail" for quotes in clue_batches for quote in quotes}
    anonymizer = FakeAnonymizer(replacements=replacements)
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Edit cap reached"
    assert [event["phase"] for event in events].count("patch_accepted") == 7
    assert len(attacker.envelopes) == 5
    assert anonymizer.calls == 7




@pytest.mark.asyncio
async def test_explicit_causal_pair_requires_exact_rank_conjunction() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.16)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.08)),
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.82)),
        ]
    )
    controller = Controller(attacker, FakeAnonymizer())
    session = confirmed_session()
    events = await collect(controller, session)
    assert events[-1]["phase"] == "run_passed"
    result = await controller.causal_test(session, CLUE)
    assert result.verdict == "causal"
    assert result.calls_used == 2
    assert len(attacker.envelopes) == 5
    assert attacker.envelopes[-2].phase == "counterfactual"
    assert attacker.envelopes[-1].phase == "control"


@pytest.mark.asyncio
async def test_causal_is_inconclusive_when_base_and_control_are_rank_two() -> None:
    attacker = FakeAttacker(
        [
            attack(
                IdentityHypothesis(identity="Someone else", confidence=0.94),
                IdentityHypothesis(identity="Mara Voss", confidence=0.80, evidence_quotes=[CLUE]),
            ),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.12)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.05)),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.05)),
            attack(
                IdentityHypothesis(identity="Someone else", confidence=0.91),
                IdentityHypothesis(identity="Mara Voss", confidence=0.80),
            ),
        ]
    )
    controller = Controller(attacker, FakeAnonymizer("regional civic data award"))
    session = confirmed_session()
    events = await collect(controller, session)
    assert events[-1]["phase"] == "run_passed"
    result = await controller.causal_test(session, CLUE)
    assert result.verdict == "inconclusive"
    assert result.calls_used == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_result",
    [
        AttackResult(returned_model="gpt-5.6-sol-test", refusal="policy refusal", latency_ms=1),
        AttackResult(returned_model="gpt-5.5", latency_ms=1),
    ],
    ids=["refusal", "model-mismatch"],
)
async def test_controller_blocks_invalid_attacker_results(invalid_result: AttackResult) -> None:
    attacker = FakeAttacker([invalid_result])
    anonymizer = FakeAnonymizer("regional civic data award")
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Verification stopped without a pass"
    assert anonymizer.calls == 0


@pytest.mark.asyncio
async def test_generated_replacement_cannot_be_retargeted_inside_a_larger_quote() -> None:
    generated = "regional civic data award"
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(
                IdentityHypothesis(
                    identity="Mara Voss",
                    confidence=0.82,
                    evidence_quotes=[f"won the {generated}"],
                )
            ),
        ]
    )
    anonymizer = FakeAnonymizer(generated)
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert [event["phase"] for event in events].count("patch_accepted") == 1
    assert events[-1]["phase"] == "run_blocked"
    assert events[-1]["title"] == "Fabricated or ambiguous clues discarded"


@pytest.mark.asyncio
async def test_exact_generated_span_can_only_revise_its_originating_patch() -> None:
    generated = "regional civic data award"
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.85, evidence_quotes=[generated])),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.15)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
        ]
    )
    anonymizer = FakeAnonymizer(generated)
    events = await collect(Controller(attacker, anonymizer), confirmed_session())
    assert events[-1]["phase"] == "run_passed"
    accepted = [event["patch"] for event in events if event["phase"] == "patch_accepted"]
    assert [patch["old_text"] for patch in accepted] == [CLUE, generated]  # type: ignore[index]
    assert anonymizer.prior_replacements == [None, generated]


@pytest.mark.asyncio
async def test_nominal_call_budget_allows_only_one_causal_pair() -> None:
    attacker = FakeAttacker(
        [
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.91, evidence_quotes=[CLUE])),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.16)),
            attack(IdentityHypothesis(identity="No supported identity", confidence=0.06)),
            attack(IdentityHypothesis(identity="Someone else", confidence=0.08)),
            attack(IdentityHypothesis(identity="Mara Voss", confidence=0.82)),
        ]
    )
    controller = Controller(attacker, FakeAnonymizer("regional civic data award"))
    session = confirmed_session()
    await collect(controller, session)
    first = await controller.causal_test(session, CLUE)
    assert first.calls_used == 2
    assert session.attacker_calls_used == 5
    with pytest.raises(ValueError, match="five-call nominal ceiling"):
        await controller.causal_test(session, CLUE)
