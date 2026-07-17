# QA: honesty-first verdict milestone

Date: 2026-07-17

## Verdict

**PASS on executed harness evidence.** The isolated correctness verifier found no correctness or security failure,
but returned `INCONCLUSIVE` because its own four-viewport Chrome run did not complete. Per the QA anti-fabrication
fallback, the verdict below uses the separately executed repository harness and does not represent the interrupted
review as an independent pass.

## Acceptance evidence

| Criterion | Result | Executed evidence |
|---|---|---|
| Product copy makes no absolute anonymity or provider claim | HOLDS | Active-copy search found no banned claim; the pass panel says it is a test result, not an anonymity guarantee. |
| Passing verdict is prominent and scoped | HOLDS | Four rendered viewports show the verdict before the document; it names GPT-5.6 reading the tested candidate and excludes external records, private databases, and auxiliary data. |
| Refusal is first-class and exact | HOLDS | Four rendered viewports show the dark refusal hero, the exact identifying sentence, why the task needs it, the external-record warning, and the no-fake/no-destroy integrity statement. No copy action is present. |
| Both recorded outcomes are reliable and synthetic | HOLDS | `/api/demo-runs/harbor` ends `run_passed`; `/api/demo-runs/task-conflict` ends `run_blocked`, retains `pass_number=0`, contains no patch, and both candidate histories omit the protected identity. |
| First-time actions use plain language | HOLDS | Browser accessibility output names `Find identifiers`, `Create private working copy`, `Test who GPT-5.6 can identify`, `Watch Cloak fix a document`, `Watch Cloak refuse a document`, `Copy tested text`, and `Restore real values`. |
| Privacy and controller invariants did not regress | HOLDS | Fresh controller traces and the 86-test backend suite preserve sanitized-only fixed GPT-5.6 envelopes, wrong-identity/fabricated-quote no-edit behavior, task-fact protection, rollback, fail-closed model checks, and exact local restore. |
| UI is responsive and accessible | HOLDS | Chrome/Playwright passed 375×667, 768×1024, 1280×720, and 1920×1080 for landing, pass, and refusal: no overflow, contrast failure, unnamed control, small mobile target, console/page error, failed request, or non-loopback request. |

Gap classifications: none (`missing=0`, `partial=0`, `contradicts=0`, `unrequested=0`).

## Gates

- Backend: 86 passed; one third-party Starlette deprecation warning.
- Frontend: 3 files, 6 tests passed.
- Production build: passed.
- Ruff and mypy: passed.
- Design lint: 0 failures. The 18 uppercase-label warnings are intentional forensic metadata, not decorative headings.
- JavaScript production audit: no known vulnerabilities.
- Python environment audit: no known vulnerabilities; the editable local package is named as skipped.
- Generic deterministic wrapper: its known secrets check flags ignored, mode-0600 `.env.local`; Git confirms the
  file is untracked. The wrapper also skips project lint/typecheck discovery, which the explicit commands above cover.

## Render evidence

- [Scoped pass, desktop](screenshots/qa-honest-verdict-passed-desktop.png)
- [Honest refusal, desktop](screenshots/qa-honest-verdict-refusal-desktop.png)
- [Scoped pass, mobile](screenshots/qa-honest-verdict-passed-mobile.png)
- [Honest refusal, mobile](screenshots/qa-honest-verdict-refusal-mobile.png)

## Boundaries

No new live GPT-5.6 call was made. Product egress was grounded with fake-client envelopes and recorded fixtures. A
real manual copy into an external assistant and rendered paste-back was not repeated in this milestone; existing exact
restore tests remain green. Intent fidelity is owned by `$loyal`; this report owns correctness and security only.
