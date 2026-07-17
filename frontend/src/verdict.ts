import type { TraceEvent } from "./types";

export type RunVerdict =
  | {
      kind: "passed";
      label: string;
      headline: string;
      explanation: string;
      testedScope: string;
      excludedScope: string;
      conflictingFacts: [];
      integrity: string;
    }
  | {
      kind: "refused";
      label: string;
      headline: string;
      explanation: string;
      testedScope: string;
      excludedScope: string;
      conflictingFacts: string[];
      integrity: string;
    };

export function verdictFrom(event: TraceEvent | undefined): RunVerdict | null {
  if (event?.phase === "run_passed") {
    return {
      kind: "passed",
      label: "Scoped pass",
      headline: "This attacker could no longer identify the subject from this text.",
      explanation:
        "GPT-5.6 omitted the protected subject during discovery and the separate holdout check. The tested replacements and task-critical facts remained intact.",
      testedScope: "GPT-5.6 reading the sanitized candidate in this run",
      excludedScope: "People or systems holding external records, private databases, or other auxiliary data",
      conflictingFacts: [],
      integrity: "This is a test result, not a guarantee that the document is anonymous.",
    };
  }

  if (event?.phase !== "run_blocked") return null;

  const conflictingFacts = Array.from(new Set(event.conflicting_facts));
  const taskConflict = conflictingFacts.length > 0;
  return {
    kind: "refused",
    label: taskConflict ? "Honest refusal" : "Not cleared to share",
    headline: taskConflict
      ? "Cloak cannot hide the subject without breaking the task."
      : "Cloak did not establish a shareable result.",
    explanation: taskConflict
      ? "The same facts that identify the subject are facts the downstream task needs. They were left unchanged."
      : event.detail,
    testedScope: taskConflict
      ? "The configured attacker still linked these facts to the protected subject"
      : "The configured attack protocol stopped before a scoped pass",
    excludedScope: taskConflict
      ? "Someone holding matching external records or web data could still re-identify the subject"
      : "No privacy conclusion can be drawn from an incomplete or blocked run",
    conflictingFacts,
    integrity: taskConflict
      ? "Cloak will not fake privacy or destroy the facts your task depends on."
      : "Cloak kept the last tested candidate and refused to present an unverified result.",
  };
}
