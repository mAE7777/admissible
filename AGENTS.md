# Cloak Working Notes

## Product invariants

- Raw text, real identifiers, surrogate vault, utility pins, and restored output stay local.
- Only sanitized candidates may enter the OpenAI attacker client.
- GPT-5.6 is fixed. A returned-model mismatch blocks the run.
- Wrong identity or ungrounded evidence never causes an edit.
- Verification copy is protocol-scoped, never an absolute anonymity claim.
- Product documents, tasks, controller behavior, and claims are English-only.
- The downstream task stays local; exact task-critical facts block a patch, and irreducible conflicts block the run.

## Stack

- Frontend: React 19.2, TypeScript, Vite 8, pnpm.
- Backend: Python 3.12, FastAPI, Pydantic 2, uv.
- Local model: `qwen3.5:4b` through Ollama on `127.0.0.1:11434`.
- Local language scope: Lingua 2.x, offline; clearly non-English documents/tasks are rejected before sealing.
- Remote attacker: GPT-5.6 through the backend only.

## Commands

- `pnpm install`
- `pnpm dev`
- `pnpm build`
- `pnpm test`
- `uv sync --project backend --all-groups`
- `uv run --project backend pytest`
- `uv run --project backend uvicorn cloak.main:app --reload --port 8787`

## Conventions

- Use Pydantic schemas at every model/network boundary.
- Stream observable run phases; never expose chain-of-thought.
- Keep live private state in memory and request logs free of document bodies.
- Use direct imports and avoid frontend barrel files.
- UI motion uses `cubic-bezier(0.16, 1, 0.3, 1)` and must honor reduced motion.
- Raw/naive benchmark attacks are limited to committed synthetic case IDs; reuse the result cache and set a hard new-call ceiling.
- Scenario acceptance is evaluation-only: committed public/synthetic fixtures and synthetic rosters only, one contract
  sanity run before the full suite, a 20-call per-scenario reservation across auxiliary-free, web-plus-64 linkage,
  and closed-world tiers, and
  zero-call cache replay after completion. The corpus hash is pinned; failed and superseded attempts retain call
  provenance and cannot overwrite the last valid result.
