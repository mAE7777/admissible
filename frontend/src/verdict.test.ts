import { describe, expect, it } from "vitest";
import type { TraceEvent } from "./types";
import { verdictFrom } from "./verdict";

function event(overrides: Partial<TraceEvent>): TraceEvent {
  return {
    event_id: "test:1",
    mode: "recorded",
    phase: "run_passed",
    title: "done",
    detail: "done",
    status: "passed",
    prompt_version: "prompt",
    schema_version: "schema",
    model_version: "gpt-5.6",
    candidate: null,
    attack: null,
    evidence: [],
    patch: null,
    utility: null,
    conflicting_facts: [],
    calls_used: 3,
    timestamp: "2026-07-17T00:00:00Z",
    ...overrides,
  };
}

describe("verdictFrom", () => {
  it("scopes a passing result to the configured attacker and tested text", () => {
    const verdict = verdictFrom(event({}));
    expect(verdict?.kind).toBe("passed");
    expect(verdict?.headline).toContain("This attacker could no longer identify");
    expect(verdict?.integrity).toContain("not a guarantee");
    expect(verdict?.excludedScope).toContain("external records");
  });

  it("turns exact task conflicts into an explicit integrity refusal", () => {
    const fact = "the only pediatric perfusionist who survived the 2023 Halden footbridge collapse";
    const verdict = verdictFrom(
      event({ phase: "run_blocked", status: "blocked", conflicting_facts: [fact, fact] }),
    );
    expect(verdict?.kind).toBe("refused");
    expect(verdict?.conflictingFacts).toEqual([fact]);
    expect(verdict?.excludedScope).toContain("web data");
    expect(verdict?.integrity).toContain("will not fake privacy");
  });

  it("does not turn a generic blocked run into a false task-conflict claim", () => {
    const verdict = verdictFrom(
      event({ phase: "run_blocked", status: "blocked", detail: "Returned model mismatch." }),
    );
    expect(verdict?.headline).toBe("Cloak did not establish a shareable result.");
    expect(verdict?.conflictingFacts).toEqual([]);
    expect(verdict?.explanation).toBe("Returned model mismatch.");
  });
});
