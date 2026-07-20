from __future__ import annotations

import os
import re
import time
from typing import Literal, Protocol

from openai import AsyncOpenAI
from openai.types.shared_params import Reasoning
from pydantic import Field

from admissible.models import (
    AttackResult,
    IdentityHypothesis,
    SanitizedEnvelope,
    StrictModel,
)

ATTACKER_MODEL = "gpt-5.6"
ATTACKER_PROMPT_VERSION = "cloak-attacker-2026-07-16.v2"
RETURNED_MODEL_PATTERN = re.compile(r"gpt-5\.6(?:-sol(?:-\d{4}-\d{2}-\d{2})?)?")


class AttackerUnavailable(RuntimeError):
    pass


class AttackerProtocolError(RuntimeError):
    pass


class AttackerOutput(StrictModel):
    hypotheses: list[IdentityHypothesis] = Field(default_factory=list, max_length=5)


class Attacker(Protocol):
    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult: ...


def model_is_gpt_56(returned_model: str) -> bool:
    return RETURNED_MODEL_PATTERN.fullmatch(returned_model) is not None


class OpenAIAttacker:
    """The only production path from a sanitized candidate to a remote service."""

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 45.0,
        holdout_timeout_seconds: float = 90.0,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.timeout_seconds = timeout_seconds
        self.holdout_timeout_seconds = holdout_timeout_seconds
        self._client = AsyncOpenAI(api_key=self.api_key, timeout=timeout_seconds) if self.api_key else None

    @property
    def ready(self) -> bool:
        return self._client is not None

    async def attack(self, envelope: SanitizedEnvelope) -> AttackResult:
        if self._client is None:
            raise AttackerUnavailable("GPT-5.6 is not configured. Set OPENAI_API_KEY and restart the local service.")
        effort: Literal["medium", "high"] = "high" if envelope.phase == "holdout" else "medium"
        started = time.monotonic()
        instructions = (
            f"Protocol {ATTACKER_PROMPT_VERSION}. You are a re-identification evaluator. "
            "Given only the sanitized document, return up to five ranked guesses for the single "
            "real person the document is about. For each guess, include only a probability and up "
            "to five exact, verbatim evidence quotes copied from the document. Never invent or "
            "paraphrase quotes. Natural-looking names, organizations, contact values, addresses, and "
            "identifier strings may be locally generated replacement values; never treat those "
            "surface values as the original identity or as evidence for it. Infer the original person "
            "only from remaining contextual clues. Order the quotes from strongest to weakest identifying clue. Do not "
            "provide hidden reasoning, analysis, or background knowledge. An empty hypotheses list "
            "is valid when the identity is not supportable."
        )
        try:
            response = await self._client.responses.parse(
                model=ATTACKER_MODEL,
                instructions=instructions,
                input=envelope.candidate_text,
                reasoning=Reasoning(effort=effort),
                text_format=AttackerOutput,
                store=False,
                timeout=self.holdout_timeout_seconds if envelope.phase == "holdout" else self.timeout_seconds,
            )
        except Exception as exc:  # SDK exceptions vary; controller still fails closed.
            raise AttackerProtocolError(f"GPT-5.6 attack failed: {type(exc).__name__}") from exc
        elapsed = int((time.monotonic() - started) * 1000)
        returned_model = response.model
        if not model_is_gpt_56(returned_model):
            raise AttackerProtocolError(f"Blocked unexpected attacker model: {returned_model}")
        parsed = response.output_parsed
        if parsed is None:
            raise AttackerProtocolError("GPT-5.6 returned no structured attack result.")
        usage: dict[str, int] = {}
        if response.usage is not None:
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        return AttackResult(
            returned_model=returned_model,
            hypotheses=parsed.hypotheses,
            latency_ms=elapsed,
            usage=usage,
        )
