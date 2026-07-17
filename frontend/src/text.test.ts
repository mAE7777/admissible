import { describe, expect, it } from "vitest";
import { codePointLength, limitCodePoints, MAX_DOCUMENT_CODEPOINTS } from "./text";

describe("Unicode code-point document limit", () => {
  it("counts astral characters as one code point", () => {
    expect(codePointLength("A😀B")).toBe(3);
  });

  it("accepts exactly 12,000 emoji and truncates only the 12,001st code point", () => {
    const atLimit = "😀".repeat(MAX_DOCUMENT_CODEPOINTS);
    expect(codePointLength(limitCodePoints(atLimit))).toBe(MAX_DOCUMENT_CODEPOINTS);
    expect(codePointLength(limitCodePoints(`${atLimit}Z`))).toBe(MAX_DOCUMENT_CODEPOINTS);
    expect(limitCodePoints(`${atLimit}Z`).endsWith("Z")).toBe(false);
  });
});
