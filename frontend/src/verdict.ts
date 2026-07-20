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
      label: "Cleared",
      headline: "Cleared. This attacker could not identify the subject from this text.",
      explanation:
        "GPT-5.6 omitted the protected subject during discovery and again in the separate holdout check. The tested replacements and every task-critical fact stayed intact.",
      testedScope: "GPT-5.6 reading the sanitized candidate in this run",
      excludedScope: "People or systems holding external records, private databases, or other auxiliary data",
      conflictingFacts: [],
      integrity: "A clearance is a ruling against the tier named above. It is not a grant of anonymity.",
    };
  }

  if (event?.phase !== "run_blocked") return null;

  const conflictingFacts = Array.from(new Set(event.conflicting_facts));
  const taskConflict = conflictingFacts.length > 0;
  return {
    kind: "refused",
    label: "Held",
    headline: taskConflict
      ? "Held. The fact that identifies them is the fact your task needs."
      : "Held. No clearance was established.",
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
      ? "The gate does not trade away the facts your task depends on to buy a clearance."
      : "The gate kept the last tested candidate rather than issue a clearance it cannot justify.",
  };
}
