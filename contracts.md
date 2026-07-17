# Contracts

## Trust boundary

- The browser talks only to the loopback FastAPI service.
- The backend is the sole holder of raw text, confirmed identifiers, utility pins, surrogate-vault values, and restored output.
- Product sessions give `OpenAIAttacker` only sanitized candidates in a `SanitizedEnvelope`; no other module can call the OpenAI client.
- The benchmark-only exception can select a committed synthetic raw fixture by case ID. Its strict empty body rejects caller-supplied document text.
- The explicit scenario-acceptance script is a second evaluation-only exception: it may send only committed
  public/synthetic fixtures, synthetic private-person rosters, and their generated task answers to GPT-5.6. It is not
  imported by the product app, accepts no caller document, and never uses real private records.
- Scenario acceptance is English-only. Its committed corpus hash is pinned and its CLI accepts no caller case file.
  Its primary evaluation stress tier gives GPT-5.6 web search and a deterministic 64-person synthetic auxiliary
  population; the auxiliary-free fictional-persona protocol remains a separate weak-evidence tier, and the unchanged
  four-person roster remains a closed-world stress tier. No tier changes the product API or egress path.
- The downstream task and task-fact profile stay local in product sessions.
- Request-body logging, analytics, remote fonts, and CDN assets are forbidden.

## Local API

| Method | Path | Result |
|---|---|---|
| POST | `/api/sessions` | Normalize and validate pasted text; return local suggestions. |
| POST | `/api/sessions/{id}/confirm` | Confirm task, subject, aliases, identifiers, and utility pins; return the first sanitized candidate. |
| POST | `/api/sessions/{id}/runs` | Stream the core attack loop as server-sent events. |
| POST | `/api/sessions/{id}/runs/{run_id}/causal` | Run one explicit counterfactual/control pair. |
| POST | `/api/sessions/{id}/restore` | Restore exact known surrogate surfaces and return diagnostics. |
| DELETE | `/api/sessions/{id}` | Destroy raw text, vault, candidates, and live trace. |
| GET | `/api/demo-runs/{slug}` | Return the sanitized `harbor` scoped-pass or `task-conflict` honest-refusal Recorded trace. |
| POST | `/api/benchmark-smoke/{case_id}/{condition}` | Attack one bundled synthetic raw or direct-identifier-only fixture; its strict empty control body rejects document text. |
| GET | `/api/health` | Report local dependencies without secrets. |

## Shared shapes

- `ProtectedSubject`: canonical identity and explicit aliases. Local only.
- `IdentifierCandidate`: suggested value, local label, occurrence count, and confirmed flag.
- `UtilityPin`: exact must-preserve text and confirmed flag.
- `SanitizedCandidate`: text, SHA-256, parent SHA-256, per-pass and cumulative edit ratios, and restore handles. The
  serialized `token_ids` field name remains for API compatibility; product values are natural surrogate surfaces.
- `AttackResult`: returned model, ranked identity hypotheses, verbatim evidence quotes, refusal/error, usage, and timing. No chain-of-thought field.
- `GroundedEvidence`: canonical quote, code-point and UTF-16 offsets, and `grounded | missing | ambiguous`.
- `PatchProposal`: exact old span and replacement plus optional exact proper-entity values to substitute; full-document rewrites are invalid.
- `UtilityLedger`: surrogate/pin integrity, normalized edit ratios, and heuristic warnings.
- `TraceEvent`: immutable `live | recorded` mode, phase, candidate hash, sanitized payload, prompt/schema/model versions, and timestamp.
- `RestoreResult`: restored text and missing, duplicated, mutated, or unknown-surrogate diagnostics.

## Controller invariants

- Input is normalized to NFC and LF once; the limit is 12,000 Unicode code points.
- Confirmation accepts the protected subject and identifier values only from the local recognizer suggestions returned
  for that session. Every alias must occur exactly, be person-like, and share a canonical name component. A caller
  cannot relabel an arbitrary amount, date, dose, role, or other task fact as a subject, alias, or identifier to bypass
  the utility floor.
- Identity matching uses NFKC, casefolding, whitespace collapse, punctuation trimming, and confirmed aliases only. No fuzzy matching.
- Evidence must occur exactly once in the normalized candidate. Missing or duplicate quotes cannot drive an edit.
- Accepted patches preserve every existing surrogate occurrence and every pin; a patch may add only staged surrogates for
  exact proper entities inside its authorized span. It changes no other text and remains at or below 20% per-pass and
  40% cumulative normalized edit distance.
- A required English downstream task is local-only. Task-sensitive numeric values, dates, durations, clinical values,
  direct statements, and chronology are hard exact constraints. Any additional model judgment may reject an edit but
  cannot waive those constraints.
- English-only scope is enforced locally before sealing with the offline Lingua detector; ambiguous one-to-three-word
  tasks are accepted only for a bounded English imperative allowlist.
- Structured money, date, duration, and clinical values are always hard constraints. Exact role, statement, relation,
  and event-polarity sentences become hard constraints when the task requests them. This intentionally blocks rather
  than risk a wrong downstream answer.
- Confirmed direct identifiers and exact proper-name or unique-entity atoms inside a uniquely grounded clue become
  session-random, type-consistent natural surrogates. Names remain names, organizations preserve useful descriptors,
  contacts use reserved fictional ranges/domains, and identifier formats retain only semantic type prefixes. Dates,
  amounts, chronology, roles, clinical facts, and other task facts are never substituted merely for realism.
  Surrogate creation is staged until every utility check passes, and rollback restores the vault to the retained candidate.
- When no surgical edit can preserve both a re-identifying fact and the task, the controller blocks and returns the
  exact conflicting fact instead of accepting semantic loss.
- A post-edit attack may not move the subject up in rank. An unchanged rank means the retired clue was only one layer of a stack, so fresh uniquely grounded clues may continue within the remaining budgets.
- A model-generated replacement is never eligible as an independent clue or as part of a larger enclosing quote. If GPT-5.6 cites the exact generated span again, provenance may invalidate and locally strengthen only that span's originating patch; it cannot authorize unrelated text. Replacements for uniqueness clues must remove rather than synonymize ordinal/superlative and demographic markers.
- At most two grounded subject clues are generalized from one attack and seven edits are accepted overall; candidate hashes cannot repeat. Every edited batch is remotely re-attacked before it can become the retained best candidate.
- The configured protocol passes only when discovery and an independent holdout both omit the subject from the top five and every invariant passes.
- Refusal, timeout, parse failure, ambiguity, model mismatch, budget exhaustion, or missing holdout fail closed.
- Remote calls are capped at five nominal and eight absolute; the holdout call is reserved.
- A scenario cache is reusable only when its case/model/protocol versions match and its recorded privacy evidence is
  internally coherent: the linkage tier has 64 candidates, at least one required web-search call, one bounded
  attacker request, consistent rank/phase/verified fields, matching candidate hashes, and reconciled total calls.
