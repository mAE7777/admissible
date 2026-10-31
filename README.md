# admissible

Check a sensitive document before you hand it to an AI.

admissible runs on your machine. You paste a document and name the person it must protect. It
replaces that person's name and other direct identifiers, such as emails, phone numbers, addresses,
ID numbers, and organizations, with natural stand-ins it can reverse. Then it asks a remote model,
GPT-5.6, to work out who the document is about, and rewrites the contextual clues that still give
the person away.

The remote model cannot edit anything. Local code checks each guess against the real identity and
each quoted clue against the text. Only then does admissible rewrite the quoted passage with a local
model, and it changes nothing else. The attacker fails when the person is not among its top five guesses. A document is
cleared only when the attacker fails twice: once in the attack-and-edit loop, and once on a separate
final attempt. You can copy out only cleared text. When the AI's answer comes back, admissible puts
the real names back on your machine.

So far, test documents clear against an attacker that reads only the text. When the attacker could
also search the web and match outside records, it identified the person in every test document, and
admissible refused to release any of them. The numbers are in [Results so far](#results-so-far).

To see it without an API key or Ollama, use the recorded demo in
[Try it without an API key or Ollama](#try-it-without-an-api-key-or-ollama).

## Local code decides every change

The remote model has no authority over your document. It makes claims, and local code checks each
claim before any text changes. The rules are code, not prompts:

- The guessed identity must match the confirmed name or one of its exact aliases (`identity_rank`).
  A wrong guess is shown and discarded. It changes nothing.
- Every quoted clue must match exactly one passage in the text (`ground_quote`). A quote that is
  missing or appears more than once is rejected, so an invented or paraphrased clue can never drive
  an edit.
- Edits stay inside the matched passage. `apply_exact_patch` is the only code path that changes the
  text, and any local patch whose `old_text` does not match that passage exactly is thrown out.
- A patch that would lose a confirmed stand-in, a fact you marked as must-keep, or a fact the task
  depends on is rejected.
- If an edit makes the person easier to identify, admissible goes back to the best version the
  attacker has already tested.
- One attacker call is reserved for the final attempt and is never spent during editing.

## Why does a privacy tool talk to OpenAI at all?

Something has to attack the document. A test against a capable model is the only evidence that the
clues are gone.

Only sanitized text crosses the boundary. Your raw text, the real identities, the table of
stand-ins, your task, and the restored output never leave your machine. The attacker is fixed to
GPT-5.6 and never falls back to another model. If it is unavailable, returns a different model,
refuses, or produces unusable evidence, admissible stops instead of quietly weakening the test.
admissible never sends anything to the AI you want to use. You copy the cleared text across
yourself.

See [contracts.md](contracts.md) for the full trust boundary.

## Results so far

A clearance means one specific attacker, with a specific amount of outside help, failed to identify
the person. It is not a promise of anonymity.

I tested five synthetic documents about fictional private people (an employment contract, a medical
summary, an asylum declaration, a credit statement, and an HR complaint) against three attackers:

| Attacker | Cleared | What happened |
|---|---|---|
| Reads only the cleaned text | 5/5 | The attacker could not name the person. This is a small fictional sample, so treat it as weak evidence. |
| Reads the text, searches the web, and gets 64 matching outside records | 0/5 | The outside records linked every person back. admissible refused to release all five. |
| Picks from a known list of four people | 0/5 | The worst case. admissible refused to release all five. |

Answers produced from the cleaned documents scored a mean 94/100 against answers from the originals.
A GPT-5.6 judge rated one of five strictly equivalent and two of five as giving the same practical
value. Several answers still left out advice that the answer from the original document gave. Real
names came back exactly in all five.

On a separate set of 15 synthetic documents about public figures, the attacker identified the person
in 100% of the original documents, 60% after a standard redaction of names and contact details, and
33% after admissible. That set was measured on 2026-07-16 with an earlier version of the controller.

The second row of the table is the main open problem. When the attacker has outside records,
admissible currently refuses rather than clears.

Every number comes from committed runs, with the raw model output and the decision on each clue:

- [Scenario report](evaluation/scenario-acceptance-report.md) and its
  [raw results](evaluation/scenario-acceptance-results.json)
- [Public-figure benchmark report](evaluation/benchmark-smoke-report.md) and its
  [raw results](evaluation/benchmark-smoke-results.json)
- [UI and controller check](evaluation/ui-and-controller-check.md)

The project was called Cloak until 2026-07-19, and the recorded evidence keeps that name.

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

Open <http://127.0.0.1:5173>. Without an OpenAI key and Ollama, the two status lights in the top bar
stay off and `/api/health` reports `degraded`. The app still runs. Choose **Watch the gate clear a
document** for a recorded run that clears, or **Watch the gate hold a document** for a recorded run
that admissible refuses because the task needs the identifying facts. Both runs are synthetic, and
the screen labels them as recorded.

`pnpm dev` starts the FastAPI backend at <http://127.0.0.1:8787> and the Vite frontend at
<http://127.0.0.1:5173>, both on loopback only. To run them separately, use `pnpm dev:api` and
`pnpm dev:web`.

## Run the live loop

Live runs also need an OpenAI API key and Ollama's `qwen3.5:4b`. Install
[Ollama](https://ollama.com/download), start it, then run:

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
| `OLLAMA_MODEL` | no | `qwen3.5:4b` | Local model that proposes edits. |

### A document, end to end

1. Paste an English document of at most 12,000 Unicode code points and choose **Find identifiers**.
2. Enter the AI task you want to perform. Confirm the person to protect, their exact aliases, the
   identifier suggestions, and any facts that must stay unchanged.
3. Choose **Create private working copy**, then **Test who GPT-5.6 can identify**.
4. Watch each guess, quoted clue, local edit, fact check, and repeat attack.
5. If the document clears, choose **Copy tested text** and paste it into your AI yourself. A refused
   document has no copy button.
6. Paste the AI's answer back and choose **Restore real values**. Restoring is local and exact.

## Test locally

The normal suite uses fakes and committed fixtures. It needs neither Ollama nor an API key and makes
no model calls.

```sh
pnpm build
pnpm test
uv run --project backend pytest
uv run --project backend ruff check backend/src backend/tests backend/scripts
uv run --project backend mypy backend/src
```

GitHub Actions runs the frontend build, the frontend tests, and the backend tests on every push and
pull request. The live soak, preflight, benchmark, and scenario scripts are not CI jobs, because they
need a local model or a paid API.

## Models

Two models do the work. Qwen3.5 4B runs locally through Ollama and proposes edits, using structured
output with thinking turned off. GPT-5.6 is the remote attacker. It uses medium reasoning for the
attacks during editing and high reasoning for the final attempt. The evaluation scripts also use
GPT-5.6 as a strict judge of answer quality, and those calls use only the committed synthetic and
public test documents.

## Project map

```text
backend/src/admissible/privacy.py           identity matching, clue matching, exact patching, and task-fact checks
backend/src/admissible/vault.py             per-session stand-ins and exact restore
backend/src/admissible/services/attacker.py the only GPT-5.6 client, which accepts sanitized text only
backend/src/admissible/services/ollama.py   local Qwen model that proposes edits
backend/src/admissible/controller.py        attack, clue check, edit, rollback, and verdict loop
backend/src/admissible/main.py              FastAPI app on loopback
frontend/src/                               React UI that shows each attack step
backend/tests/                              controller and boundary regression tests
evaluation/                                 synthetic test documents, raw results, and reports
```

## Scope

- English pasted text only. One protected person per session, kept in memory for one hour.
- Exact alias matching. No fuzzy identity matching and no file upload.
- No automatic sending to ChatGPT or any other assistant.
- At most eight attacker calls per document, five in a normal run. The optional check of whether
  one clue caused the guess uses two of those five.
- No protection is promised against outside records, data brokers, an attacker who already has a
  short list of candidates, or future attackers.

The benchmark and scenario scripts are the one exception to the sanitized-only rule. They work only
on the committed synthetic and public test documents, and neither accepts a document you supply.

## License

[MIT](LICENSE)
