import { useEffect, useMemo, useState } from "react";
import { api, copyPayload, streamRun, TOKEN_INSTRUCTION } from "./api";
import { codePointLength, limitCodePoints, MAX_DOCUMENT_CODEPOINTS } from "./text";
import { verdictFrom, type RunVerdict } from "./verdict";
import type {
  CausalResult,
  Health,
  RestoreResult,
  SanitizedCandidate,
  SessionDraft,
  TraceEvent,
} from "./types";

type Stage = "paste" | "review" | "ready" | "running" | "finished";

const SAMPLE = `Mara Voss led the Harborlight reporting project from her office at Westbridge College. She won the 2019 Northshore Civic Data Prize and later taught the Tuesday night newsroom lab. Contact: mara.voss@example.com.`;

function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [stage, setStage] = useState<Stage>("paste");
  const [draftText, setDraftText] = useState("");
  const [session, setSession] = useState<SessionDraft | null>(null);
  const [subject, setSubject] = useState("");
  const [aliases, setAliases] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [task, setTask] = useState("");
  const [pins, setPins] = useState("");
  const [candidate, setCandidate] = useState<SanitizedCandidate | null>(null);
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [mode, setMode] = useState<"live" | "recorded">("live");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [restoreInput, setRestoreInput] = useState("");
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);
  const [causal, setCausal] = useState<Record<string, CausalResult | "loading">>({});

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  const finalEvent = events.at(-1);
  const verdict = verdictFrom(finalEvent);
  const draftCodePoints = codePointLength(draftText);
  const hasPassed = finalEvent?.phase === "run_passed";
  const runId = events[0]?.event_id.split(":")[0] ?? "";
  const causalCalls = Object.values(causal).reduce(
    (total, result) => total + (result === "loading" ? 0 : result.calls_used),
    0,
  );
  const groundedClues = useMemo(
    () =>
      Array.from(
        new Set(
          events.flatMap((event) =>
            event.evidence.filter((item) => item.status === "grounded").map((item) => item.quote),
          ),
        ),
      ),
    [events],
  );

  async function prepareDocument() {
    setBusy(true);
    setError("");
    try {
      const next = await api.createSession(draftText);
      setSession(next);
      const suggested = next.subject_suggestions[0] ?? "";
      setSubject(suggested);
      setSelectedIds(
        new Set(
          next.identifier_candidates
            .filter((item) => item.label !== "Person" || item.value === suggested)
            .map((item) => item.candidate_id),
        ),
      );
      setStage("review");
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }

  async function confirmDocument() {
    if (!session) return;
    setBusy(true);
    setError("");
    try {
      const response = await api.confirm(session.session_id, {
        subject: {
          canonical_identity: subject,
          aliases: aliases
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean),
        },
        identifiers: session.identifier_candidates
          .filter((item) => selectedIds.has(item.candidate_id))
          .map((item) => item.value),
        task: task.trim(),
        pins: pins
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
      });
      setCandidate(response.candidate);
      setStage("ready");
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }

  async function startAttack() {
    if (!session || !health?.attacker_ready) return;
    setMode("live");
    setStage("running");
    setEvents([]);
    setError("");
    setCausal({});
    try {
      await streamRun(session.session_id, (event) => {
        setEvents((current) => [...current, event]);
        if (event.candidate) setCandidate(event.candidate);
        if (event.phase === "run_passed" || event.phase === "run_blocked") {
          setStage("finished");
        }
      });
    } catch (cause) {
      setError(message(cause));
      setStage("finished");
    }
  }

  async function loadRecorded(slug: "harbor" | "task-conflict") {
    setBusy(true);
    setError("");
    try {
      const demo = await api.demo(slug);
      setMode("recorded");
      setEvents(demo.events);
      setCandidate(demo.events.at(-1)?.candidate ?? null);
      setStage("finished");
      setSession(null);
      setSubject(demo.protected_subject);
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(false);
    }
  }

  async function copyCandidate() {
    if (!candidate) return;
    await navigator.clipboard.writeText(copyPayload(candidate.text, candidate.token_ids));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  async function restoreTokens() {
    if (!session) return;
    setError("");
    try {
      setRestoreResult(await api.restore(session.session_id, restoreInput));
    } catch (cause) {
      setError(message(cause));
    }
  }

  async function testCausality(quote: string) {
    if (!session || !runId) return;
    setCausal((current) => ({ ...current, [quote]: "loading" }));
    try {
      const result = await api.causal(session.session_id, runId, quote);
      setCausal((current) => ({ ...current, [quote]: result }));
    } catch (cause) {
      setCausal((current) => ({
        ...current,
        [quote]: { verdict: "inconclusive", detail: message(cause), calls_used: 0, counterfactual: null, control: null },
      }));
    }
  }

  async function reset() {
    if (session) await api.destroy(session.session_id);
    setStage("paste");
    setDraftText("");
    setSession(null);
    setCandidate(null);
    setEvents([]);
    setError("");
    setRestoreInput("");
    setRestoreResult(null);
    setMode("live");
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="wordmark" onClick={reset} aria-label="Start over">
          admissible<span className="wordmark-mark">/</span>
        </button>
        <p className="promise">Original text, real identifiers, the replacement map, and restored answers stay on this device.</p>
        <div className="health" aria-label="System status">
          <StatusDot ready={health?.ollama_ready} label={health ? health.ollama_model : "Local model"} />
          <StatusDot ready={health?.attacker_ready} label="GPT-5.6" />
        </div>
      </header>

      <main className="workspace">
        <section className="document-pane" aria-label="Document workspace">
          <div className="document-heading">
            <div>
              <span className="eyebrow">Document / {stageLabel(stage)}</span>
              <h1>{documentTitle(stage)}</h1>
            </div>
            {candidate && (
              <span className="pass-count">
                {candidate.pass_number} {candidate.pass_number === 1 ? "edit" : "edits"}
              </span>
            )}
          </div>

          {stage === "paste" && (
            <div className="paste-stage">
              <p className="landing-thesis">
                Admissible shows how GPT-5.6 can identify someone, fixes only the clues your task can spare,
                and refuses when privacy would require damaging the document.
              </p>
              <textarea
                className="document-input"
                value={draftText}
                onChange={(event) => setDraftText(limitCodePoints(event.target.value))}
                placeholder="Paste a document. Nothing is uploaded when you paste."
                aria-label="Sensitive document"
                aria-describedby="document-character-count"
              />
              <div className="input-footer">
                <span id="document-character-count">
                  English only · {draftCodePoints.toLocaleString()} / {MAX_DOCUMENT_CODEPOINTS.toLocaleString()} characters
                </span>
                <button className="text-button" onClick={() => setDraftText(SAMPLE)}>
                  Paste a sample document
                </button>
              </div>
              <div className="primary-row">
                <button className="primary-button" disabled={!draftText.trim() || busy} onClick={prepareDocument}>
                  {busy ? "Finding identifiers…" : "Find identifiers"}
                </button>
                <button className="secondary-button" disabled={busy} onClick={() => loadRecorded("harbor")}>
                  Watch the gate clear a document
                </button>
                <button className="refusal-button" disabled={busy} onClick={() => loadRecorded("task-conflict")}>
                  Watch the gate hold a document
                </button>
              </div>
            </div>
          )}

          {stage === "review" && session && (
            <div className="review-stage">
              <div className="field-pair">
                <label>
                  <span>Protected subject</span>
                  <input value={subject} onChange={(event) => setSubject(event.target.value)} />
                </label>
                <label>
                  <span>Exact aliases <small>comma separated</small></span>
                  <input value={aliases} onChange={(event) => setAliases(event.target.value)} placeholder="M. Voss, Voss" />
                </label>
              </div>
              <fieldset className="identifier-list">
                <legend>Identifiers found on this device</legend>
                {session.identifier_candidates.length ? (
                  session.identifier_candidates.map((item) => (
                    <label className="identifier-row" key={item.candidate_id}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(item.candidate_id)}
                        onChange={() =>
                          setSelectedIds((current) => {
                            const next = new Set(current);
                            next.has(item.candidate_id) ? next.delete(item.candidate_id) : next.add(item.candidate_id);
                            return next;
                          })
                        }
                      />
                      <span className="identifier-label">{item.label}</span>
                      <code>{item.value}</code>
                      <span>×{item.occurrence_count}</span>
                    </label>
                  ))
                ) : (
                  <p className="quiet">No obvious identifiers found. Admissible will still replace the protected subject locally.</p>
                )}
              </fieldset>
              <label className="pin-field">
                <span>What do you want the AI to do? <small>required · stays local</small></span>
                <textarea
                  value={task}
                  onChange={(event) => setTask(event.target.value)}
                  placeholder="What should the downstream AI do with this document? Admissible uses this to lock the facts the answer needs."
                />
              </label>
              <label className="pin-field">
                <span>Facts that must not change <small>one exact phrase per line</small></span>
                <textarea value={pins} onChange={(event) => setPins(event.target.value)} placeholder="One task-critical fact per line" />
              </label>
              <button className="primary-button" disabled={!subject.trim() || !task.trim() || busy} onClick={confirmDocument}>
                {busy ? "Creating working copy…" : "Create private working copy"}
              </button>
            </div>
          )}

          {(stage === "ready" || stage === "running" || stage === "finished") && candidate && (
            <div className="candidate-stage">
              {stage === "finished" && verdict && <VerdictPanel verdict={verdict} />}
              <article className="paper-copy">{candidate.text}</article>
              <div className="candidate-meta">
                <span>{candidate.token_ids.length} restorable surrogate occurrences</span>
                <span>{Math.round(candidate.cumulative_edit_ratio * 100)}% cumulative edit distance</span>
                <span>sha {candidate.sha256.slice(0, 8)}</span>
              </div>
              {stage === "ready" && (
                <div className="run-gate">
                  <p>
                    GPT-5.6 receives only this working copy. The original text, identity, task, and replacement map stay local.
                  </p>
                  <button
                    className="primary-button"
                    disabled={!health?.attacker_ready}
                    onClick={startAttack}
                  >
                    Test who GPT-5.6 can identify
                  </button>
                  {!health?.attacker_ready && (
                    <p className="blocked-note">OPENAI_API_KEY is missing. Live verification stays blocked; no fallback model will run.</p>
                  )}
                </div>
              )}
              {hasPassed && (
                <div className="handoff">
                  <div>
                    <span className="eyebrow">Manual handoff</span>
                    <h2>Use the tested text in your AI</h2>
                    <p>{TOKEN_INSTRUCTION}</p>
                  </div>
                  <button className="primary-button" onClick={copyCandidate}>
                    {copied ? "Copied with instructions" : "Copy tested text"}
                  </button>
                </div>
              )}
              {hasPassed && mode === "live" && (
                <div className="restore-panel">
                  <label>
                    <span>Paste the AI response to put real values back</span>
                    <textarea
                      value={restoreInput}
                      onChange={(event) => setRestoreInput(event.target.value)}
                      placeholder="The response remains local while surrogate values are restored."
                    />
                  </label>
                  <button className="secondary-button" disabled={!restoreInput} onClick={restoreTokens}>
                    Restore real values
                  </button>
                  {restoreResult && <RestoreReport result={restoreResult} />}
                </div>
              )}
              {mode === "recorded" && (
                <p className="recorded-warning">Recorded synthetic text has no live surrogate vault and cannot be restored.</p>
              )}
            </div>
          )}

          {error && <p className="error-banner" role="alert">{error}</p>}
        </section>

        <aside className="attack-rail" aria-label="Re-identification attack trace">
          <div className="rail-heading">
            <div>
              <span className="eyebrow">Attack theater</span>
              <h2>Who does GPT-5.6 think this is?</h2>
            </div>
            <span className={`mode-label ${mode}`}>{mode === "live" ? "Live" : "Recorded · synthetic"}</span>
          </div>

          {!events.length ? (
            <div className="empty-trace">
              <div className="trace-reticle" aria-hidden="true"><span /></div>
              <p>The attacker’s guess, exact clue, and every decision to change or preserve the text will appear here.</p>
              <ol>
                <li><span>01</span> Guess an identity</li>
                <li><span>02</span> Ground the claimed clue</li>
                <li><span>03</span> Change one authorized span</li>
                <li><span>04</span> Re-attack and hold out</li>
              </ol>
            </div>
          ) : (
            <div className="trace" aria-live="polite">
              {events.map((event, index) => (
                <TraceRow event={event} index={index} key={event.event_id} />
              ))}
            </div>
          )}

          {mode === "live" && groundedClues.length > 0 && stage === "finished" && (
            <div className="causal-lab">
              <span className="eyebrow">Optional deepening · +2 calls</span>
              <h3>Did the clue actually cause the guess?</h3>
              <p>A counterfactual and matched control run in parallel. Only the exact rank-one rule counts.</p>
              {groundedClues.slice(0, 3).map((quote) => (
                <div className="causal-item" key={quote}>
                  <q>{quote}</q>
                  <button
                    className="rail-button"
                    disabled={causal[quote] === "loading" || (finalEvent?.calls_used ?? 0) + causalCalls + 2 > 5}
                    onClick={() => testCausality(quote)}
                  >
                    {causal[quote] === "loading"
                      ? "Checking clue…"
                      : (finalEvent?.calls_used ?? 0) + causalCalls + 2 > 5
                        ? "Nominal call budget used"
                        : "Check whether this clue caused the guess"}
                  </button>
                  {causal[quote] && causal[quote] !== "loading" && (
                    <p className={`causal-result ${causal[quote].verdict}`}>
                      {causal[quote].verdict.replace("_", " ")} — {causal[quote].detail}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}

          <footer className="rail-footer">
            <span>5 nominal · 8 absolute</span>
            <span>{(finalEvent?.calls_used ?? 0) + causalCalls} used</span>
          </footer>
        </aside>
      </main>
    </div>
  );
}

function VerdictPanel({ verdict }: { verdict: RunVerdict }) {
  const headingId = `verdict-${verdict.kind}-heading`;
  return (
    <section
      className={`verdict-panel verdict-${verdict.kind}`}
      aria-labelledby={headingId}
      aria-live="polite"
      data-verdict={verdict.kind}
    >
      <div className="verdict-mark" aria-hidden="true">{verdict.kind === "passed" ? "✓" : "×"}</div>
      <div className="verdict-copy">
        <span className="verdict-label">Final verdict / {verdict.label}</span>
        <h2 id={headingId}>{verdict.headline}</h2>
        <p className="verdict-explanation">{verdict.explanation}</p>

        {verdict.conflictingFacts.length > 0 && (
          <div className="verdict-conflicts">
            <h3>The facts Admissible refused to remove</h3>
            <ul>
              {verdict.conflictingFacts.map((fact) => <li key={fact}>{fact}</li>)}
            </ul>
          </div>
        )}

        <dl className="verdict-scope">
          <div>
            <dt>{verdict.kind === "passed" ? "What was tested" : "Why it stopped"}</dt>
            <dd>{verdict.testedScope}</dd>
          </div>
          <div>
            <dt>{verdict.kind === "passed" ? "What this does not prove" : "What remains exposed"}</dt>
            <dd>{verdict.excludedScope}</dd>
          </div>
        </dl>
        <p className="verdict-integrity">{verdict.integrity}</p>
      </div>
    </section>
  );
}

function TraceRow({ event, index }: { event: TraceEvent; index: number }) {
  return (
    <section className={`trace-row status-${event.status}`}>
      <div className="trace-index">{String(index + 1).padStart(2, "0")}</div>
      <div className="trace-body">
        <div className="trace-title-line">
          <h3>{event.title}</h3>
          <span>{event.attack ? `${(event.attack.latency_ms / 1000).toFixed(1)}s` : event.status}</span>
        </div>
        <p>{event.detail}</p>
        {event.attack && event.attack.hypotheses.length > 0 && (
          <div className="guess-list">
            {event.attack.hypotheses.map((guess, guessIndex) => (
              <div className="guess" key={`${guess.identity}-${guessIndex}`}>
                <span>#{guessIndex + 1}</span>
                <strong>{guess.identity}</strong>
                <em>{Math.round(guess.confidence * 100)}%</em>
              </div>
            ))}
          </div>
        )}
        {event.evidence.map((evidence) => (
          <div className={`evidence ${evidence.status}`} key={`${event.event_id}-${evidence.quote}`}>
            <span>{evidence.status === "grounded" ? "Exact clue" : "Rejected clue"}</span>
            <q>{evidence.quote}</q>
            {evidence.codepoint_start !== null && <code>{evidence.codepoint_start}:{evidence.codepoint_end}</code>}
          </div>
        ))}
        {event.conflicting_facts.map((fact) => (
          <div className="evidence missing" key={`${event.event_id}-conflict-${fact}`}>
            <span>Required by task</span>
            <q>{fact}</q>
          </div>
        ))}
        {event.patch && (
          <div className="diff-view">
            <div><span>−</span><del>{event.patch.old_text}</del></div>
            <div><span>+</span><ins>{event.patch.replacement}</ins></div>
          </div>
        )}
        {event.utility && (
          <div className="utility-line">
            <span>surrogates {event.utility.tokens_intact ? "intact" : "changed"}</span>
            <span>pins {event.utility.pins_intact ? "intact" : "lost"}</span>
            <span>{Math.round(event.utility.cumulative_edit_ratio * 100)}% / 40% budget</span>
            {event.utility.heuristic_warnings.map((warning) => <span key={warning}>{warning}</span>)}
          </div>
        )}
      </div>
    </section>
  );
}

function RestoreReport({ result }: { result: RestoreResult }) {
  const issueCount = result.missing_tokens.length + result.duplicated_tokens.length + result.mutated_tokens.length + result.unknown_tokens.length;
  return (
    <div className="restore-report">
      <div className="restore-status">
        <strong>{issueCount ? "Restored with diagnostics" : "Exact known surrogates restored"}</strong>
        <span>{result.restored_count} replacements</span>
      </div>
      <pre>{result.restored_text}</pre>
      {issueCount > 0 && (
        <ul>
          {result.missing_tokens.length > 0 && <li>{result.missing_tokens.length} missing surrogate values</li>}
          {result.duplicated_tokens.length > 0 && <li>{result.duplicated_tokens.length} duplicated surrogate values</li>}
          {result.mutated_tokens.length > 0 && <li>{result.mutated_tokens.length} altered surrogate-like values</li>}
          {result.unknown_tokens.length > 0 && <li>{result.unknown_tokens.length} unknown legacy token types</li>}
        </ul>
      )}
    </div>
  );
}

function StatusDot({ ready, label }: { ready?: boolean; label: string }) {
  return <span className="status-dot"><i className={ready ? "ready" : "off"} />{label}</span>;
}

function stageLabel(stage: Stage) {
  return { paste: "paste", review: "confirm", ready: "working copy", running: "under attack", finished: "result" }[stage];
}

function documentTitle(stage: Stage) {
  return {
    paste: "See what this document gives away.",
    review: "Choose what Admissible may replace.",
    ready: "Private working copy",
    running: "Testing the working copy",
    finished: "Final verdict",
  }[stage];
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : "Admissible stopped without a verdict.";
}

export default App;
