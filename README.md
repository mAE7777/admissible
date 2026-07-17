# Cloak

Cloak is a local privacy gatekeeper for English documents: watch GPT-5.6 try to identify the subject, fix the clues that can be changed safely, and see an honest verdict.
It does not promise anonymity; when privacy and the document's purpose conflict, it refuses instead of hiding the conflict or destroying the document.

Cloak is strongest at replacing direct identifiers and defeating an attacker that has only the sanitized text. It is
not protection against an employer, data broker, or other attacker holding a matching outside record. The final
verdict states which threat was actually tested.

## What happens to your document

- Raw text, the real identity, the downstream task, utility-protected facts, the surrogate vault, and restored output
  stay in memory on your machine.
- Names and unique entities become consistent, natural-looking surrogates so another AI can still read the document.
- Only sanitized candidates are sent to the fixed GPT-5.6 attacker. Cloak never sends a document to your preferred AI
  and never falls back to another attacker model.
- GPT-5.6 must quote each identifying clue exactly. The local controller must match the guessed identity to local
  ground truth and map every quote to one unique character span before an edit is allowed.
- Task-critical amounts, dates, chronology, roles, clinical facts, and direct statements are protected. If one is also
  identifying, Cloak blocks and names the conflict.
- Known surrogates restore to the exact original wording after you paste an AI's answer back into Cloak.

The bundled benchmark and acceptance scripts are explicit exceptions for committed synthetic/public fixtures only.
They cannot accept a caller-supplied document through the product API.

## Try the recorded runs — no Ollama or API key

You need [Node.js 22](https://nodejs.org/en/download/archive/v22), pnpm 10.17, and
[uv](https://docs.astral.sh/uv/getting-started/installation/). `uv` installs the pinned Python 3.12 runtime if it is
missing.

```sh
git clone https://github.com/YOUR_ACCOUNT/cloak.git
cd cloak
corepack enable
corepack prepare pnpm@10.17.0 --activate
pnpm install --frozen-lockfile
uv sync --project backend --frozen --all-groups
pnpm dev
```

Open <http://127.0.0.1:5173>. The health indicator will be degraded without the two live model dependencies, but the
application still works. Choose **Watch Cloak fix a document** for the scoped-pass trace or **Watch Cloak refuse a
document** for the task-conflict trace. Both are recorded, synthetic, and labelled as such.

The combined command starts:

- the loopback FastAPI backend at <http://127.0.0.1:8787>;
- the Vite frontend at <http://127.0.0.1:5173>.

To run them separately, use `pnpm dev:api` and `pnpm dev:web` in two terminals.

## Run the live loop

Live runs additionally require an OpenAI API key and Ollama's `qwen3.5:4b` model. Install
[Ollama](https://ollama.com/download); on Linux, the official installer is:

```sh
curl -fsSL https://ollama.com/install.sh | sh
```

Start the Ollama app, or run `ollama serve`, then download the exact local model:

```sh
ollama pull qwen3.5:4b
ollama list
```

Create a local configuration file. It is ignored by Git and is not loaded automatically, so source it before
starting Cloak:

```sh
cp .env.example .env.local
# Edit .env.local and replace the OPENAI_API_KEY placeholder.
set -a
. ./.env.local
set +a
pnpm dev
```

The variables are:

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `OPENAI_API_KEY` | live runs | none | Authenticates the fixed GPT-5.6 attacker. |
| `OLLAMA_BASE_URL` | no | `http://127.0.0.1:11434` | Local Ollama API. |
| `OLLAMA_MODEL` | no | `qwen3.5:4b` | Local patch proposer. |

### Run a document end to end

1. Paste an English document of at most 12,000 Unicode code points and choose **Find identifiers**.
2. Enter the AI task you want to perform. Confirm one protected subject, their exact aliases, identifier suggestions,
   and any facts that must remain unchanged.
3. Choose **Create private working copy**, then **Test who GPT-5.6 can identify**.
4. Watch each guess, exact clue, local edit, utility decision, and re-attack. A pass requires both discovery and a
   separate high-effort holdout to omit the subject from the top five.
5. If the verdict clears the tested text, choose **Copy tested text** and paste it manually into your preferred AI.
6. Paste that AI's answer into Cloak and choose **Restore real values**. Restoration happens locally.

If GPT-5.6 is unavailable, returns a different model, refuses, or produces unusable evidence, the controller blocks.
If Ollama is unavailable, Cloak cannot propose a live generalization and blocks rather than silently weakening the
protocol.

## Evidence, including the ceiling

These are small smoke/acceptance sets, not anonymity guarantees or population estimates. The reports and cached model
outputs are committed so the numbers are inspectable.

| Evaluation | Result | Honest reading |
|---|---|---|
| Historical 15-case re-identification smoke set | raw 100% → direct-ID baseline 60% → Cloak 33% | Cloak reached 0/5 re-identifications on direct-PII controls, but 4/5 aggregate public-figure profiles remained identifiable because their biographies were the task's substance. This is historical controller-v9 evidence. |
| Five private-person scenarios, attacker sees only sanitized text | 5/5 privacy passes | Supports the narrow text-only claim on this fictional sample; it is weak evidence, not a validated rate. |
| Same scenarios, web search plus a 64-record auxiliary population | 0/5 privacy passes; all 5 blocked honestly | Matching outside records relinked every persona. Cloak preserved task facts and refused instead of claiming safety. |
| Same scenarios, closed four-person roster | 0/5 privacy passes; all 5 blocked honestly | The explicit worst-case boundary. |
| Downstream utility and restore | mean 94/100; 1/5 strict equivalence; 2/5 same practical value; 5/5 exact restore | Natural surrogates preserve facts and restore exactly, but one-shot downstream answers still omitted material advice in several scenarios. |

Whole-workflow acceptance under the stronger auxiliary-record threat was **0/5**, so Cloak is an honest prototype, not
a production-validated anonymizer. Read the current
[scenario acceptance report](qa-reports/scenario-acceptance-report.md), the historical
[benchmark report](qa-reports/benchmark-smoke-report.md), and the
[UI/controller QA report](qa-reports/qa-honesty-verdict.md) for case-level results and limitations.

## How I built it with Codex and GPT-5.6

Codex built the codebase from scratch under my direction: the local controller, privacy checks, attack trace,
surrogate vault, exact restore path, UI, tests, and evaluation harnesses. The initial research pass used moderate
depth; the controller failures, threat-model split, and utility regressions got deeper implementation and verification
passes. The repository does not record a stable Codex model identifier, so I am not inventing one here.

I pushed back when early results looked better than the product was: a 53% post-Cloak re-identification rate, early
stopping on stacked clues, task-fact deletion that produced wrong answers, opaque tokens that degraded downstream
reasoning, and a fictional-persona privacy test that ignored external records. Those failures drove rollback-to-best,
multi-clue progress, hard task-fact protection, natural surrogates, the stronger linkage tier, and the prominent honest
refusal.

The product models are explicit. Qwen3.5 4B runs locally through Ollama with deterministic structured output and no
thinking mode. GPT-5.6 is the remote live adversary: medium reasoning for discovery and post-edit attacks, high
reasoning for the final holdout. GPT-5.6 also acts as the strict comparison judge in the opt-in acceptance harness;
those calls use only committed synthetic/public fixtures.

## Test locally

The normal build and test suite uses fakes and committed fixtures. It requires neither Ollama nor an OpenAI key and
makes no model calls.

```sh
pnpm build
pnpm test
uv run --project backend pytest
uv run --project backend ruff check backend/src backend/tests backend/scripts
uv run --project backend mypy backend/src
```

GitHub Actions runs the frontend build/tests and backend tests on every push and pull request. The live soak,
preflight, benchmark, and acceptance scripts are intentionally not CI jobs because they require local or paid model
services.

## Project map

```text
backend/src/cloak/privacy.py          deterministic recognition and utility checks
backend/src/cloak/vault.py            session-random natural surrogates and exact restore
backend/src/cloak/services/attacker.py fixed sanitized-only GPT-5.6 boundary
backend/src/cloak/services/ollama.py   local Qwen patch proposer
backend/src/cloak/controller.py       attack, grounding, edit, rollback, and verdict loop
backend/src/cloak/main.py             loopback FastAPI API
frontend/src/                         React attack-theater UI
backend/tests/                         controller and boundary regression tests
qa-reports/                            curated synthetic evidence and current reports
```

## Scope

- English pasted text only; one protected subject per in-memory, one-hour session.
- Exact alias matching; no fuzzy identity match and no file upload.
- No automatic send to ChatGPT, Claude, Gemini, or another assistant.
- A five-call nominal and eight-call absolute attacker budget; the optional causal pair consumes two calls.
- No promise against outside records, data brokers, a known candidate roster, or future attackers.

See [contracts.md](contracts.md) for the trust boundary and controller invariants.

## License

[MIT](LICENSE)
