import type {
  CausalResult,
  ConfirmResponse,
  Health,
  RecordedRun,
  RestoreResult,
  SessionDraft,
  TraceEvent,
} from "./types";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `Request failed (${response.status})`);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => requestJson<Health>("/api/health"),
  createSession: (text: string) =>
    requestJson<SessionDraft>("/api/sessions", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  confirm: (
    sessionId: string,
    body: {
      subject: { canonical_identity: string; aliases: string[] };
      identifiers: string[];
      pins: string[];
      task: string;
    },
  ) =>
    requestJson<ConfirmResponse>(`/api/sessions/${sessionId}/confirm`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  demo: (slug: "harbor" | "task-conflict") => requestJson<RecordedRun>(`/api/demo-runs/${slug}`),
  restore: (sessionId: string, text: string) =>
    requestJson<RestoreResult>(`/api/sessions/${sessionId}/restore`, {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  causal: (sessionId: string, runId: string, quote: string) =>
    requestJson<CausalResult>(`/api/sessions/${sessionId}/runs/${runId}/causal`, {
      method: "POST",
      body: JSON.stringify({ quote }),
    }),
  destroy: async (sessionId: string) => {
    await fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
  },
};

export async function streamRun(
  sessionId: string,
  onEvent: (event: TraceEvent) => void,
): Promise<void> {
  const response = await fetch(`/api/sessions/${sessionId}/runs`, { method: "POST" });
  if (!response.ok || !response.body) {
    throw new Error(`Attack stream failed (${response.status})`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value, { stream: !done });
    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() ?? "";
    for (const block of blocks) {
      const data = block
        .split("\n")
        .find((line) => line.startsWith("data: "))
        ?.slice(6);
      if (data) onEvent(JSON.parse(data) as TraceEvent);
    }
    if (done) break;
  }
}

export const TOKEN_INSTRUCTION =
  "This document uses Admissible replacement names and identifiers. Keep each replacement exactly spelled whenever you use it so Admissible can restore the original locally; do not try to identify the originals.";

export function copyPayload(candidate: string, handles: string[] = []): string {
  const references = Array.from(new Set(handles));
  const referenceLine = references.length ? `\nAdmissible replacements: ${references.join(" · ")}` : "";
  return `${TOKEN_INSTRUCTION}${referenceLine}\n\n${candidate}`;
}
