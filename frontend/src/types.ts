export type Health = {
  status: "ready" | "degraded";
  ollama_ready: boolean;
  ollama_model: string;
  attacker_ready: boolean;
  attacker_model: "gpt-5.6";
  privacy_boundary: string;
};

export type IdentifierCandidate = {
  candidate_id: string;
  label: string;
  value: string;
  occurrence_count: number;
  confirmed: boolean;
};

export type SessionDraft = {
  session_id: string;
  normalized_text: string;
  char_count: number;
  subject_suggestions: string[];
  identifier_candidates: IdentifierCandidate[];
};

export type SanitizedCandidate = {
  text: string;
  sha256: string;
  parent_sha256: string | null;
  pass_number: number;
  per_pass_edit_ratio: number;
  cumulative_edit_ratio: number;
  token_ids: string[];
};

export type Hypothesis = {
  identity: string;
  confidence: number;
  evidence_quotes: string[];
};

export type AttackResult = {
  requested_model: string;
  returned_model: string;
  hypotheses: Hypothesis[];
  refusal: string | null;
  error: string | null;
  latency_ms: number;
  usage: Record<string, number>;
};

export type Evidence = {
  quote: string;
  status: "grounded" | "missing" | "ambiguous";
  codepoint_start: number | null;
  codepoint_end: number | null;
  utf16_start: number | null;
  utf16_end: number | null;
};

export type PatchProposal = {
  old_text: string;
  replacement: string;
  rationale: string;
  tokenize_values: string[];
};

export type UtilityLedger = {
  accepted: boolean;
  reasons: string[];
  tokens_intact: boolean;
  pins_intact: boolean;
  authorized_span_only: boolean;
  per_pass_edit_ratio: number;
  cumulative_edit_ratio: number;
  heuristic_warnings: string[];
};

export type TraceEvent = {
  event_id: string;
  mode: "live" | "recorded";
  phase: string;
  title: string;
  detail: string;
  status: "active" | "passed" | "blocked" | "changed" | "info";
  prompt_version: string;
  schema_version: string;
  model_version: string;
  candidate: SanitizedCandidate | null;
  attack: AttackResult | null;
  evidence: Evidence[];
  patch: PatchProposal | null;
  utility: UtilityLedger | null;
  conflicting_facts: string[];
  calls_used: number;
  timestamp: string;
};

export type ConfirmResponse = {
  session_id: string;
  candidate: SanitizedCandidate;
  confirmed_identifiers: number;
  confirmed_pins: number;
};

export type RecordedRun = {
  slug: string;
  label: string;
  protected_subject: string;
  events: TraceEvent[];
};

export type RestoreResult = {
  restored_text: string;
  restored_count: number;
  missing_tokens: string[];
  duplicated_tokens: string[];
  mutated_tokens: string[];
  unknown_tokens: string[];
};

export type CausalResult = {
  verdict: "causal" | "not_causal" | "inconclusive";
  detail: string;
  calls_used: number;
  counterfactual: AttackResult | null;
  control: AttackResult | null;
};
