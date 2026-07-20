from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from admissible.models import SanitizedEnvelope
from admissible.services.attacker import ATTACKER_MODEL, AttackerOutput, OpenAIAttacker, model_is_gpt_56


class FakeResponses:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    async def parse(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return SimpleNamespace(
            model="gpt-5.6-sol-2026-07-01",
            output_parsed=AttackerOutput(hypotheses=[]),
            usage=SimpleNamespace(input_tokens=10, output_tokens=5, total_tokens=15),
        )


@pytest.mark.asyncio
async def test_remote_boundary_is_fixed_and_receives_only_sanitized_envelope() -> None:
    responses = FakeResponses()
    client = SimpleNamespace(responses=responses)
    attacker = OpenAIAttacker(api_key="test")
    attacker._client = client  # type: ignore[assignment]
    envelope = SanitizedEnvelope(
        candidate_text="[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]] won a regional award.",
        candidate_sha256="a" * 64,
        phase="discovery",
    )
    result = await attacker.attack(envelope)
    assert ATTACKER_MODEL == "gpt-5.6"
    assert responses.kwargs["model"] == "gpt-5.6"
    assert responses.kwargs["input"] == envelope.candidate_text
    assert responses.kwargs["store"] is False
    assert responses.kwargs["timeout"] == 45.0
    assert result.returned_model.startswith("gpt-5.6-sol")
    assert set(responses.kwargs).isdisjoint({"ground_truth", "aliases", "raw_text"})


@pytest.mark.asyncio
async def test_high_effort_holdout_has_a_separate_bounded_timeout() -> None:
    responses = FakeResponses()
    attacker = OpenAIAttacker(api_key="test", timeout_seconds=45, holdout_timeout_seconds=90)
    attacker._client = SimpleNamespace(responses=responses)  # type: ignore[assignment]
    await attacker.attack(
        SanitizedEnvelope(
            candidate_text="A sanitized candidate.",
            candidate_sha256="b" * 64,
            phase="holdout",
        )
    )
    assert responses.kwargs["reasoning"]["effort"] == "high"
    assert responses.kwargs["timeout"] == 90


def test_model_mismatch_is_rejected() -> None:
    assert model_is_gpt_56("gpt-5.6-sol-2026-07-01")
    assert model_is_gpt_56("gpt-5.6-sol")
    assert not model_is_gpt_56("gpt-5.5")
    assert not model_is_gpt_56("gpt-5.6-terra")
    assert not model_is_gpt_56("gpt-5.6-solar-bogus")
