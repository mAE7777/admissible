from __future__ import annotations

import argparse
import asyncio
import statistics
import time

from cloak.services.ollama import OllamaAnonymizer

CANDIDATE = (
    "[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]] led a reporting project for a regional newsroom. "
    "The subject won the 2019 Northshore Civic Data Prize after public records work and "
    "later taught a recurring newsroom lab."
)
CLUE = "2019 Northshore Civic Data Prize"


async def main(calls: int) -> int:
    anonymizer = OllamaAnonymizer()
    durations: list[float] = []
    failures: list[str] = []
    for index in range(calls):
        started = time.monotonic()
        try:
            patch = await anonymizer.propose_patch(CANDIDATE, CLUE)
            if patch.old_text != CLUE or not patch.replacement.strip():
                raise ValueError(
                    "schema passed but exact clue contract failed: "
                    f"old_text={patch.old_text!r} replacement={patch.replacement!r}"
                )
            state = "ok"
        except Exception as exc:
            failures.append(f"{index + 1}: {type(exc).__name__}: {exc}")
            state = "failed"
        elapsed = time.monotonic() - started
        durations.append(elapsed)
        print(f"call {index + 1:02d}/{calls}: {state} {elapsed:.2f}s", flush=True)
    ordered = sorted(durations)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    print(
        f"summary calls={calls} failures={len(failures)} median={statistics.median(durations):.2f}s p95={p95:.2f}s",
        flush=True,
    )
    for failure in failures:
        print(failure, flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=10)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.calls)))
