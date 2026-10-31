# admissible

**The gate between your sensitive documents and the AI you want to use.**

Put your real work in front of a frontier model. What clears, cleared against a live attack. What
doesn't, never leaves. What comes back is yours again.

> **Evaluating this for Build Week?** You can run it with **no OpenAI key and no Ollama**. Jump to
> [Try it](#try-it-without-an-api-key-or-ollama): it plays two real recorded attack traces (one
> cleared, one held) plus a built-in sample document. The live loop needs only your own OpenAI key
> and is optional for evaluation.

Removing the name is not enough: a capable model can infer who you are from everything else the
document says. So admissible works on both layers. It redacts (names become natural, reversible
surrogates, and the clues that give a person away are generalized), but it refuses to stop there
and call the result clean, the way every redaction tool does. It attacks its own redaction with a real GPT-5.6 adversary, rules on whether the redaction
actually held, and closes the handoff on anything that does not clear. What clears comes back to you
exactly, real names restored.

## How the ruling is earned

The remote model has **no authority over your document.** It cannot edit anything. It asserts, and
a local controller adjudicates every assertion before a single character moves. The rules are code,
not prompts, and you can read them:

- The guessed identity must match local ground truth (`identity_rank`). A wrong guess is shown and
  discarded; it authorizes nothing.
- Every claimed clue must resolve to **exactly one** span in the text (`ground_quote`). Missing and
  ambiguous quotes are both rejected, so a fabricated or paraphrased "gotcha" can never drive an edit.
- Edits are written only inside the authorized span (`apply_exact_patch` is the sole mutation path),
  and any local patch whose `old_text` does not match that span exactly is thrown out.
- Any patch that would lose a confirmed pin or an identified task-critical fact is rejected.
- If the subject's rank gets *worse*, the last remotely-tested best candidate is restored.
- One attacker call is permanently reserved for an independent holdout and is never spent on
  discovery. A clearance requires a discovery miss **and** that separate holdout miss.

## Why does a privacy tool talk to OpenAI at all?

Because something has to actually attack the document, and a real attack is the only thing that
earns a ruling.

Only **sanitized candidates** cross the boundary. Your raw text, the real identities, the surrogate
vault, your downstream task, and the restored output never leave your machine. The attacker is
fixed to GPT-5.6 and never falls back to another model; if it is unavailable, returns a different
model, refuses, or produces unusable evidence, the controller blocks rather than quietly weakening
the protocol. `admissible` never sends anything to your preferred AI; you copy the cleared text
across yourself.

See [contracts.md](contracts.md) for the full trust boundary.

## What a clearance means, and the number that goes with it

A clearance is a **ruling against a named tier**, not a grant of anonymity.

The tier this project's own acceptance report calls **primary** is a web-enabled attacker with a
64-record auxiliary population. **At that tier the gate currently clears nothing: 0/5, with
whole-workflow acceptance also 0/5.** That is the gate's current yield and the largest open problem
in this project. It is stated here, on the first screen, because burying it would make every other
number meaningless.

| Evaluation | Result | Honest reading |
|---|---|---|
| Auxiliary-free tier (attacker sees only the sanitized text), five private-person scenarios | 5/5 cleared | Supports the narrow text-only claim on a small fictional sample. Weak evidence, not a validated rate. |
| **Primary tier: web search + a 64-record auxiliary population** | **0/5** | Matching outside records relinked every persona. The gate held all five and named the conflict. |
| Closed four-person roster (5 scenarios) | 0/5 cleared | The explicit worst-case boundary; all five held. |
| Downstream utility and restore | mean 94/100; 1/5 strict equivalence; 2/5 same practical value; **5/5 exact restore** | Natural surrogates preserve the facts and restore exactly; one-shot answers still omitted material advice in several scenarios. |
| Historical 15-case re-identification smoke set | raw 100% → direct-ID baseline 60% → 33% | Historical controller-v9 evidence. |

So: what clears is genuinely earned against a real adversary plus a holdout. How *often* the gate
clears, at the harder tier, is today essentially never. Those are two different facts and both are
above the fold.

## Read the actual attack transcripts

Every number above comes from committed runs, not from a summary. The raw model outputs, the
per-clue grounding decisions, and the block reasons are all in the repo:

- [scenario acceptance report](evaluation/scenario-acceptance-report.md) and its
  [raw results](evaluation/scenario-acceptance-results.json)
- [benchmark report](evaluation/benchmark-smoke-report.md) and its
  [raw results](evaluation/benchmark-smoke-results.json)
- [UI and controller QA](evaluation/ui-and-controller-check.md)

> **Note on the name.** This project was built and evaluated under the name `cloak` and renamed to
> `admissible` on 2026-07-19. Everything in `evaluation/` is preserved exactly as it was recorded,
> including the old name in schema versions, condition keys, and cached model output. Evidence of a
> run is not edited after the fact.

## Try it without an API key or Ollama

You need [Node.js 22](https://nodejs.org/en/download/archive/v22), pnpm 10.17, and
[uv](https://docs.astral.sh/uv/getting-started/installation/). `uv` installs the pinned Python 3.12
runtime if it is missing.

```sh
git clone https://github.com/mAE7777/admissible.git
cd admissible
corepack enable
corepack prepare pnpm@10.17.0 --activate
pnpm install --frozen-lockfile
uv sync --project backend --frozen --all-groups
pnpm dev
```

If `corepack` is unavailable, install pnpm 10.17 directly and skip the two `corepack` lines.

Open <http://127.0.0.1:5173>. The health indicator reports **degraded** without the two live model
dependencies, which is correct and visible by design; the app still runs. Choose **Watch the gate
clear a document** for the cleared trace, or **Watch the gate hold a document** for the
task-conflict trace. Both are recorded, synthetic, and labelled as such on screen.

The combined command starts the loopback FastAPI backend at <http://127.0.0.1:8787> and the Vite
frontend at <http://127.0.0.1:5173>. Run them separately with `pnpm dev:api` and `pnpm dev:web`.

## Run the live loop

Live runs additionally need an OpenAI API key and Ollama's `qwen3.5:4b`. Install
[Ollama](https://ollama.com/download), start it, then:

```sh
ollama pull qwen3.5:4b
cp .env.example .env.local     # then put your real key in .env.local
set -a; . ./.env.local; set +a
pnpm dev
```

`.env.local` is git-ignored and is not loaded automatically, so source it before starting.

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `OPENAI_API_KEY` | live runs | none | Authenticates the fixed GPT-5.6 attacker. |
| `OLLAMA_BASE_URL` | no | `http://127.0.0.1:11434` | Local Ollama API. |
| `OLLAMA_MODEL` | no | `qwen3.5:4b` | Local patch proposer. |

### A document, end to end

1. Paste an English document of at most 12,000 Unicode code points and choose **Find identifiers**.
2. Enter the AI task you actually want to perform. Confirm one protected subject, their exact
   aliases, the identifier suggestions, and any facts that must survive unchanged.
3. Choose **Create private working copy**, then **Test who GPT-5.6 can identify**.
4. Watch each guess, exact clue, local edit, utility decision, and re-attack.
5. If the gate clears it, **Copy tested text** and paste it into your preferred AI yourself. On a
   held document that action is not offered.
6. Paste the AI's answer back and choose **Restore real values**. Restoration is local and exact.

## Test locally

The normal suite uses fakes and committed fixtures. It needs neither Ollama nor an API key and
makes no model calls.

```sh
pnpm build
pnpm test
uv run --project backend pytest
uv run --project backend ruff check backend/src backend/tests backend/scripts
uv run --project backend mypy backend/src
```

GitHub Actions runs the frontend build/tests and backend tests on every push and pull request. The
live soak, preflight, benchmark, and acceptance scripts are intentionally not CI jobs because they
require local or paid model services.

## How I built it with Codex and GPT-5.6

Codex built this codebase from scratch under my direction: the local controller, the privacy checks,
the attack trace, the surrogate vault, the exact restore path, the UI, the tests, and the evaluation
harnesses. The initial research pass used moderate depth; the controller failures, the threat-model
split, and the utility regressions got deeper implementation and verification passes. The repository
does not record a stable Codex model identifier, so I am not inventing one here.

I pushed back when early results looked better than the product was: a 53% post-sanitization
re-identification rate, early stopping on stacked clues, task-fact deletion that produced wrong
answers, opaque tokens that degraded downstream reasoning, and a fictional-persona privacy test that
ignored external records. Those failures drove rollback-to-best, multi-clue progress, hard task-fact
protection, natural surrogates, the stronger linkage tier, and the enforced hold. That adversarial
loop ran throughout development, not only at the end: pointing the GPT-5.6 attacker at each
Codex-built control is what surfaced those failures, so GPT-5.6 was a build-time collaborator as
much as the product's runtime adversary.

The product models are explicit. Qwen3.5 4B runs locally through Ollama with deterministic
structured output and no thinking mode. GPT-5.6 is the remote live adversary: medium reasoning for
discovery and post-edit attacks, high reasoning for the final holdout. GPT-5.6 also acts as the
strict comparison judge in the opt-in acceptance harness; those calls use only committed
synthetic/public fixtures.

## Project map

```text
backend/src/admissible/privacy.py           deterministic recognition and utility checks
backend/src/admissible/vault.py             session-random natural surrogates and exact restore
backend/src/admissible/services/attacker.py fixed sanitized-only GPT-5.6 boundary
backend/src/admissible/services/ollama.py   local Qwen patch proposer
backend/src/admissible/controller.py        attack, grounding, edit, rollback, and ruling loop
backend/src/admissible/main.py              loopback FastAPI API
frontend/src/                               React attack-theater UI
backend/tests/                              controller and boundary regression tests
evaluation/                                 curated synthetic evidence and current reports
```

## Scope

- English pasted text only; one protected subject per in-memory, one-hour session.
- Exact alias matching; no fuzzy identity match and no file upload.
- No automatic send to ChatGPT or another assistant.
- A five-call nominal and eight-call absolute attacker budget; the optional causal pair uses two.
- No promise against outside records, data brokers, a known candidate roster, or future attackers.

The bundled benchmark and acceptance scripts are explicit exceptions for committed
synthetic/public fixtures only. They cannot accept a caller-supplied document through the product API.

## License

[MIT](LICENSE)
