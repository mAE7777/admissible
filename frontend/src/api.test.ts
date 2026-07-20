import { describe, expect, it } from "vitest";
import { copyPayload, TOKEN_INSTRUCTION } from "./api";

describe("copyPayload", () => {
  it("always places the surrogate-preservation instruction before the candidate", () => {
    const candidate = "Ask Avery Vale for a summary.";
    const payload = copyPayload(candidate, ["Avery Vale"]);
    expect(payload.startsWith(TOKEN_INSTRUCTION)).toBe(true);
    expect(payload).toContain("Admissible replacements: Avery Vale");
    expect(payload.endsWith(candidate)).toBe(true);
  });
});
