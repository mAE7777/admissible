from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import AsyncIterator
from typing import Literal

from admissible.models import (
    AttackResult,
    CausalResult,
    GroundedEvidence,
    PatchProposal,
    SanitizedCandidate,
    SanitizedEnvelope,
    TraceEvent,
    UtilityLedger,
)
from admissible.privacy import (
    apply_exact_patch,
    candidate_from_text,
    check_utility,
    deterministic_task_facts,
    ground_quote,
    identity_rank,
    sha256_text,
    tokenizable_specifics,
)
from admissible.services.attacker import Attacker, AttackerProtocolError, model_is_gpt_56
from admissible.services.ollama import LocalAnonymizer
from admissible.sessions import Session

MAX_CALLS = 8
NOMINAL_MAX_CALLS = 5
MAX_EDITS = 7
MAX_PATCHES_PER_ATTACK = 2
CONTROLLER_PROTOCOL_VERSION = "cloak-core-2026-07-16.v11"


def _event(
    *,
    run_id: str,
    phase: str,
    title: str,
    detail: str,
    status: Literal["active", "passed", "blocked", "changed", "info"],
    calls: int,
    candidate: SanitizedCandidate | None = None,
    attack: AttackResult | None = None,
    evidence: list[GroundedEvidence] | None = None,
    patch: PatchProposal | None = None,
    utility: UtilityLedger | None = None,
    conflicting_facts: list[str] | None = None,
) -> TraceEvent:
    return TraceEvent(
        event_id=f"{run_id}:{phase}:{uuid.uuid4().hex[:6]}",
        mode="live",
        phase=phase,
        title=title,
        detail=detail,
        status=status,
        calls_used=calls,
        candidate=candidate,
        attack=attack,
        evidence=evidence or [],
        patch=patch,
        utility=utility,
        conflicting_facts=conflicting_facts or [],
    )


def _sse(event: TraceEvent) -> str:
    return f"event: trace\ndata: {event.model_dump_json()}\n\n"


def _subject_confidence(result: AttackResult, aliases: list[str]) -> tuple[int | None, float]:
    rank = identity_rank([item.identity for item in result.hypotheses], aliases)
    if rank is None:
        return None, 0.0
    return rank, result.hypotheses[rank - 1].confidence


def validate_attack_result(result: AttackResult) -> None:
    if result.requested_model != "gpt-5.6" or not model_is_gpt_56(result.returned_model):
        raise AttackerProtocolError(f"Blocked unexpected attacker model: {result.returned_model}")
    if result.refusal:
        raise AttackerProtocolError("GPT-5.6 refused the re-identification request.")
    if result.error:
        raise AttackerProtocolError("GPT-5.6 returned an attack error.")


def _contains_generated_text(quote: str, generated_spans: set[str]) -> bool:
    return any(span in quote or quote in span for span in generated_spans)


class Controller:
    def __init__(self, attacker: Attacker, anonymizer: LocalAnonymizer) -> None:
        self.attacker = attacker
        self.anonymizer = anonymizer

    async def run(self, session: Session) -> AsyncIterator[str]:
        run_id = uuid.uuid4().hex
        session.last_run_id = run_id
        if session.subject is None or session.candidate is None or session.original_sanitized is None:
            raise ValueError("Confirm the protected subject before starting the attack.")
        candidate = session.candidate
        best_candidate = candidate
        aliases = [session.subject.canonical_identity, *session.subject.aliases]
        expected_tokens = session.candidate.token_ids
        seen_hashes = {candidate.sha256}
        calls = 0
        edits = 0
        previous_rank: int | None = None
        generated_spans: set[str] = set()
        generated_origins: dict[str, str] = {}
        run_task_conflicts: list[str] = []
        session.last_evidence = []
        session.causal_candidates = {}
        session.causal_base_ranks = {}
        session.attacker_calls_used = 0

        yield _sse(
            _event(
                run_id=run_id,
                phase="run_started",
                title="Only the working copy leaves the local boundary",
                detail="The attacker receives the sanitized candidate; original values and the task stay local.",
                status="info",
                calls=calls,
                candidate=candidate,
            )
        )

        session.task_facts = deterministic_task_facts(session.task, candidate.text)
        yield _sse(
            _event(
                run_id=run_id,
                phase="utility_profile",
                title="Task-critical facts locked locally",
                detail=(
                    f"{len(session.task_facts)} exact numeric, chronological, or direct-statement facts must survive "
                    "every privacy edit. The task and this "
                    "utility profile stay local."
                ),
                status="info",
                calls=calls,
                candidate=candidate,
            )
        )

        try:
            while calls < MAX_CALLS - 1:  # reserve one call for the holdout
                phase: Literal["discovery", "post_edit"] = "discovery" if edits == 0 else "post_edit"
                yield _sse(
                    _event(
                        run_id=run_id,
                        phase="attacking",
                        title="GPT-5.6 is attacking",
                        detail="Requesting five identity guesses and exact supporting quotes.",
                        status="active",
                        calls=calls,
                        candidate=candidate,
                    )
                )
                attack = await self.attacker.attack(
                    SanitizedEnvelope(
                        candidate_text=candidate.text,
                        candidate_sha256=candidate.sha256,
                        phase=phase,
                    )
                )
                calls += 1
                session.attacker_calls_used = calls
                validate_attack_result(attack)
                rank, _confidence = _subject_confidence(attack, aliases)
                yield _sse(
                    _event(
                        run_id=run_id,
                        phase="attack_result",
                        title="Attacker returned its guesses",
                        detail=(
                            f"The protected subject appears at rank {rank}."
                            if rank is not None
                            else "None of the five guesses matches local ground truth."
                        ),
                        status="blocked" if rank is not None else "passed",
                        calls=calls,
                        candidate=candidate,
                        attack=attack,
                    )
                )

                rank_worsened = previous_rank is not None and rank is not None and rank < previous_rank
                if rank_worsened:
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="run_blocked",
                            title="The edit made re-identification easier",
                            detail="The subject moved up in rank, so Admissible restored the previous best candidate.",
                            status="blocked",
                            calls=calls,
                            candidate=best_candidate,
                        )
                    )
                    candidate = best_candidate
                    session.vault.retain_candidate(best_candidate.text)
                    session.candidate = best_candidate
                    return

                if previous_rank is not None:
                    best_candidate = candidate

                if previous_rank is not None and rank == previous_rank:
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="rank_unchanged",
                            title="One layer fell; the clue stack held",
                            detail=(
                                "Rank is unchanged, but the prior grounded span is gone. Admissible will retire fresh "
                                "grounded clues within the remaining privacy and utility budgets."
                            ),
                            status="info",
                            calls=calls,
                            candidate=candidate,
                        )
                    )

                if rank is None:
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="guess_rejected",
                            title="No local identity match",
                            detail=(
                                "Wrong guesses are displayed but cannot trigger an edit. Running the reserved holdout."
                            ),
                            status="passed",
                            calls=calls,
                            candidate=candidate,
                        )
                    )
                    holdout = await self.attacker.attack(
                        SanitizedEnvelope(
                            candidate_text=candidate.text,
                            candidate_sha256=candidate.sha256,
                            phase="holdout",
                        )
                    )
                    calls += 1
                    session.attacker_calls_used = calls
                    validate_attack_result(holdout)
                    holdout_rank, _ = _subject_confidence(holdout, aliases)
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="holdout",
                            title="Independent holdout finished",
                            detail=(
                                "The holdout also omitted the protected subject from its top five."
                                if holdout_rank is None
                                else f"The holdout recovered the protected subject at rank {holdout_rank}."
                            ),
                            status="passed" if holdout_rank is None else "blocked",
                            calls=calls,
                            candidate=candidate,
                            attack=holdout,
                        )
                    )
                    final_phase = "run_passed" if holdout_rank is None else "run_blocked"
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase=final_phase,
                            title=(
                                "This attacker could no longer identify the subject"
                                if holdout_rank is None
                                else "Verification blocked"
                            ),
                            detail=(
                                "Discovery and holdout both omitted the subject. This result is scoped to GPT-5.6 "
                                "reading the tested text, not an attacker holding external records."
                                if holdout_rank is None
                                else "The candidate is not cleared to copy because the holdout recovered the subject."
                            ),
                            status="passed" if holdout_rank is None else "blocked",
                            calls=calls,
                            candidate=candidate,
                        )
                    )
                    session.candidate = candidate
                    return

                hypothesis = attack.hypotheses[rank - 1]
                evidence = [ground_quote(candidate.text, quote) for quote in hypothesis.evidence_quotes]
                edit_targets: list[tuple[GroundedEvidence, str, str | None]] = []
                fresh_grounded: list[GroundedEvidence] = []
                for item in evidence:
                    if item.status != "grounded":
                        continue
                    original_clue = generated_origins.get(item.quote)
                    if original_clue is not None:
                        edit_targets.append((item, original_clue, item.quote))
                    elif not _contains_generated_text(item.quote, generated_spans):
                        edit_targets.append((item, item.quote, None))
                        fresh_grounded.append(item)
                session.last_evidence = [item.quote for item in fresh_grounded]
                yield _sse(
                    _event(
                        run_id=run_id,
                        phase="evidence_grounding",
                        title="Every claimed clue checked locally",
                        detail=(
                            f"{sum(item.status == 'grounded' for item in evidence)} of "
                            f"{len(evidence)} quotes map to one exact span."
                        ),
                        status="passed" if edit_targets else "blocked",
                        calls=calls,
                        candidate=candidate,
                        evidence=evidence,
                    )
                )
                if not edit_targets:
                    unique_conflicts = list(dict.fromkeys(run_task_conflicts))[:10]
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="run_blocked",
                            title=(
                                "Privacy and task utility conflict"
                                if unique_conflicts
                                else "Fabricated or ambiguous clues discarded"
                            ),
                            detail=(
                                "Admissible kept the exact required fact instead of returning a wrong answer: "
                                + " | ".join(unique_conflicts[:3])
                                if unique_conflicts
                                else "The identity guess may be correct, but no claimed clue can authorize an edit."
                            ),
                            status="blocked",
                            calls=calls,
                            candidate=candidate,
                            conflicting_facts=unique_conflicts,
                        )
                    )
                    session.candidate = candidate
                    return
                for grounded in fresh_grounded:
                    session.causal_candidates[grounded.quote] = candidate
                    session.causal_base_ranks[grounded.quote] = rank
                if edits >= MAX_EDITS:
                    unique_conflicts = list(dict.fromkeys(run_task_conflicts))[:10]
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="run_blocked",
                            title="Privacy and task utility conflict" if unique_conflicts else "Edit cap reached",
                            detail=(
                                "Admissible kept the exact required fact instead of returning a wrong answer: "
                                + " | ".join(unique_conflicts[:3])
                                if unique_conflicts
                                else "Seven grounded edits were not enough; Admissible stopped rather than erase more "
                                "of the document."
                            ),
                            status="blocked",
                            calls=calls,
                            candidate=candidate,
                            conflicting_facts=unique_conflicts,
                        )
                    )
                    session.candidate = candidate
                    return
                if calls >= MAX_CALLS - 1:
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="run_blocked",
                            title="Call budget exhausted",
                            detail="No tested edit can be made while still reserving the independent holdout call.",
                            status="blocked",
                            calls=calls,
                            candidate=candidate,
                        )
                    )
                    session.candidate = candidate
                    return
                previous_rank = rank
                patches_this_attack = 0
                task_conflicts: list[str] = []
                for grounded, original_clue, prior_replacement in edit_targets:
                    if patches_this_attack >= MAX_PATCHES_PER_ATTACK or edits >= MAX_EDITS:
                        break
                    current_grounded = ground_quote(candidate.text, grounded.quote)
                    if current_grounded.status != "grounded":
                        continue
                    protected_in_quote = [
                        fact if fact in current_grounded.quote else current_grounded.quote
                        for fact in [*session.pins, *session.task_facts]
                        if fact in current_grounded.quote or current_grounded.quote in fact
                    ]
                    protected_in_quote = list(dict.fromkeys(protected_in_quote))
                    surrogate_handles = session.vault.handles_in_text(current_grounded.quote)
                    proper_specifics = (
                        tokenizable_specifics(current_grounded.quote, protected_in_quote)
                        if protected_in_quote
                        else []
                    )
                    if proper_specifics:
                        patch = PatchProposal(
                            old_text=current_grounded.quote,
                            replacement=current_grounded.quote,
                            rationale="Substitute exact identifying entities while preserving the task facts.",
                            tokenize_values=proper_specifics,
                        )
                    elif protected_in_quote:
                        task_conflicts.extend(protected_in_quote)
                        run_task_conflicts.extend(protected_in_quote)
                        yield _sse(
                            _event(
                                run_id=run_id,
                                phase="patch_rejected",
                                title="Task-critical clue kept intact",
                                detail="This clue cannot be changed without removing facts required by the task.",
                                status="info",
                                calls=calls,
                                candidate=candidate,
                                evidence=[current_grounded],
                                conflicting_facts=protected_in_quote,
                            )
                        )
                        continue
                    else:
                        try:
                            patch = await self.anonymizer.propose_patch(
                                candidate.text,
                                original_clue,
                                prior_replacement=prior_replacement,
                                task=session.task,
                                protected_facts=[*protected_in_quote, *surrogate_handles],
                            )
                        except Exception as exc:
                            yield _sse(
                                _event(
                                    run_id=run_id,
                                    phase="patch_rejected",
                                    title="Local generalization skipped",
                                    detail=f"This clue could not be generalized locally: {type(exc).__name__}.",
                                    status="info",
                                    calls=calls,
                                    candidate=candidate,
                                    evidence=[current_grounded],
                                )
                            )
                            continue
                    if patch.old_text != current_grounded.quote:
                        yield _sse(
                            _event(
                                run_id=run_id,
                                phase="patch_rejected",
                                title="Local patch rejected",
                                detail="The anonymizer did not return the exact authorized clue span.",
                                status="info",
                                calls=calls,
                                candidate=candidate,
                                evidence=[current_grounded],
                                patch=patch,
                            )
                        )
                        continue
                    try:
                        effective_replacement, staged_tokens = session.vault.stage_fragment_tokenization(
                            patch.replacement,
                            patch.tokenize_values,
                        )
                    except ValueError:
                        yield _sse(
                            _event(
                                run_id=run_id,
                                phase="patch_rejected",
                                title="Local surrogate proposal rejected",
                                detail="A proposed restorable entity was not an exact value inside the grounded clue.",
                                status="info",
                                calls=calls,
                                candidate=candidate,
                                evidence=[current_grounded],
                                patch=patch,
                            )
                        )
                        continue
                    patch = patch.model_copy(update={"replacement": effective_replacement})
                    proposed_text = apply_exact_patch(candidate.text, current_grounded, effective_replacement)
                    staged_occurrences = [
                        handle
                        for handle in staged_tokens
                        for _occurrence in range(effective_replacement.count(handle))
                    ]
                    utility = check_utility(
                        previous=candidate.text,
                        proposed=proposed_text,
                        original_sanitized=session.original_sanitized,
                        pins=[*session.pins, *session.task_facts],
                        expected_tokens=[*expected_tokens, *staged_occurrences],
                        authorized_quote=current_grounded,
                        replacement=effective_replacement,
                    )
                    if not utility.accepted:
                        lost_task_facts = [fact for fact in protected_in_quote if fact not in effective_replacement]
                        task_conflicts.extend(lost_task_facts)
                        run_task_conflicts.extend(lost_task_facts)
                        yield _sse(
                            _event(
                                run_id=run_id,
                                phase="patch_rejected",
                                title="Utility budget kept this clue intact",
                                detail="Admissible skipped this proposal and checked the next grounded clue.",
                                status="info",
                                calls=calls,
                                candidate=candidate,
                                evidence=[current_grounded],
                                patch=patch,
                                utility=utility,
                            )
                        )
                        continue
                    next_candidate = candidate_from_text(
                        proposed_text,
                        original_text=session.original_sanitized,
                        pass_number=candidate.pass_number + 1,
                        parent_sha256=candidate.sha256,
                        previous_text=candidate.text,
                        restore_handles=[*session.vault.known_handles, *staged_tokens],
                    )
                    if next_candidate.sha256 in seen_hashes:
                        yield _sse(
                            _event(
                                run_id=run_id,
                                phase="patch_rejected",
                                title="Repeated candidate skipped",
                                detail="This document state was already tested, so Admissible tried another clue.",
                                status="info",
                                calls=calls,
                                candidate=candidate,
                                evidence=[current_grounded],
                                patch=patch,
                                utility=utility,
                            )
                        )
                        continue
                    seen_hashes.add(next_candidate.sha256)
                    if prior_replacement is not None:
                        generated_spans.discard(prior_replacement)
                        generated_origins.pop(prior_replacement, None)
                    generated_spans.add(patch.replacement)
                    generated_origins[patch.replacement] = original_clue
                    candidate = next_candidate
                    session.vault.commit_staged_tokens(staged_tokens, candidate.text)
                    expected_tokens = candidate.token_ids
                    edits += 1
                    patches_this_attack += 1
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="patch_accepted",
                            title="One grounded clue generalized",
                            detail=(
                                "The exact span changed; surrogates, pins, grammar checks, and the utility budget pass."
                            ),
                            status="changed",
                            calls=calls,
                            candidate=candidate,
                            evidence=[current_grounded],
                            patch=patch,
                            utility=utility,
                        )
                    )
                if patches_this_attack == 0:
                    unique_conflicts = list(dict.fromkeys([*run_task_conflicts, *task_conflicts]))[:10]
                    yield _sse(
                        _event(
                            run_id=run_id,
                            phase="run_blocked",
                            title=(
                                "Privacy and task utility conflict"
                                if unique_conflicts
                                else "No utility-bounded clue edit was available"
                            ),
                            detail=(
                                "Admissible kept the exact required fact instead of returning a wrong answer: "
                                + " | ".join(unique_conflicts[:3])
                                if unique_conflicts
                                else "Every fresh grounded proposal failed a local grammar, surrogate, pin, span, or "
                                "edit budget check."
                            ),
                            status="blocked",
                            calls=calls,
                            candidate=candidate,
                            conflicting_facts=unique_conflicts,
                        )
                    )
                    session.candidate = candidate
                    return
        except Exception as exc:
            candidate = best_candidate
            session.vault.retain_candidate(best_candidate.text)
            yield _sse(
                _event(
                    run_id=run_id,
                    phase="run_blocked",
                    title="Verification stopped without a pass",
                    detail=str(exc),
                    status="blocked",
                    calls=calls,
                    candidate=best_candidate,
                )
            )
            session.candidate = best_candidate
            return

        yield _sse(
            _event(
                run_id=run_id,
                phase="run_blocked",
                title="Call budget exhausted",
                detail="The reserved holdout could not complete within the eight-call ceiling.",
                status="blocked",
                calls=calls,
                candidate=candidate,
            )
        )
        session.candidate = candidate

    async def causal_test(self, session: Session, quote: str) -> CausalResult:
        if session.subject is None or session.candidate is None:
            raise ValueError("Run the core verification loop first.")
        if quote not in session.last_evidence:
            raise ValueError("Causal tests are limited to grounded clues from the latest attack.")
        if session.attacker_calls_used + 2 > NOMINAL_MAX_CALLS:
            raise ValueError("The counterfactual pair would exceed the five-call nominal ceiling.")
        base_candidate = session.causal_candidates.get(quote)
        if base_candidate is None:
            raise ValueError("The sanitized candidate for this clue is no longer available.")
        base_rank = session.causal_base_ranks.get(quote)
        if base_rank is None:
            raise ValueError("The base attack rank for this clue is unavailable.")
        grounded = ground_quote(base_candidate.text, quote)
        if grounded.status != "grounded":
            raise ValueError("The selected clue is no longer a unique span in the current candidate.")
        counterfactual_text = apply_exact_patch(base_candidate.text, grounded, "a comparable professional detail")
        control_span = self._control_span(base_candidate.text, quote)
        if control_span is None:
            return CausalResult(
                verdict="inconclusive",
                detail="No eligible matched-control span was available in this document.",
                calls_used=0,
            )
        control_grounded = ground_quote(base_candidate.text, control_span)
        control_text = apply_exact_patch(base_candidate.text, control_grounded, "a separate contextual detail")
        session.attacker_calls_used += 2
        counterfactual, control = await asyncio.gather(
            self.attacker.attack(
                SanitizedEnvelope(
                    candidate_text=counterfactual_text,
                    candidate_sha256=sha256_text(counterfactual_text),
                    phase="counterfactual",
                )
            ),
            self.attacker.attack(
                SanitizedEnvelope(
                    candidate_text=control_text,
                    candidate_sha256=sha256_text(control_text),
                    phase="control",
                )
            ),
        )
        validate_attack_result(counterfactual)
        validate_attack_result(control)
        aliases = [session.subject.canonical_identity, *session.subject.aliases]
        counterfactual_rank, _ = _subject_confidence(counterfactual, aliases)
        control_rank, _ = _subject_confidence(control, aliases)
        if base_rank == 1 and counterfactual_rank is None and control_rank == 1:
            verdict: Literal["causal", "not_causal", "inconclusive"] = "causal"
            detail = "Base and control rank the subject first; removing the clue drops it from the top five."
        elif base_rank == 1 and counterfactual_rank is not None and control_rank == 1:
            verdict = "not_causal"
            detail = "Removing this clue did not remove the subject from the top five."
        else:
            verdict = "inconclusive"
            detail = "The base and control did not both retain the subject at rank one."
        return CausalResult(
            verdict=verdict,
            detail=detail,
            calls_used=2,
            counterfactual=counterfactual,
            control=control,
        )

    @staticmethod
    def _control_span(candidate: str, excluded: str) -> str | None:
        target_words = min(12, max(3, len(re.findall(r"[\w'-]+", excluded))))
        for sentence in re.split(r"(?<=[.!?])\s+", candidate):
            clean = sentence.strip()
            if excluded in clean or "[[CX_" in clean:
                continue
            words = list(re.finditer(r"[\w'-]+", clean))
            if len(words) < target_words:
                continue
            for start_index in range(len(words) - target_words + 1):
                window = words[start_index : start_index + target_words]
                span = clean[window[0].start() : window[-1].end()]
                if candidate.count(span) == 1:
                    return span
        return None


def parse_sse_payload(stream: str) -> list[dict[str, object]]:
    """Small helper used by tests and the recorded-demo builder."""
    return [json.loads(line[6:]) for line in stream.splitlines() if line.startswith("data: ")]
