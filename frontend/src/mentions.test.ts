import { describe, expect, it } from "vitest";
import { replacedValueMentions } from "./mentions";

describe("replaced-value mentions in the task and pins", () => {
  it("finds a replaced value the task mentions, case-insensitively", () => {
    expect(replacedValueMentions("Summarize the complaint against ACME Corp", "", ["Acme Corp"])).toEqual([
      "Acme Corp",
    ]);
  });

  it("finds a replaced value mentioned only in the pins", () => {
    expect(replacedValueMentions("Draft a reply", "keep Mara Voss informed", ["Mara Voss"])).toEqual([
      "Mara Voss",
    ]);
  });

  it("returns nothing when neither field mentions a replaced value", () => {
    expect(replacedValueMentions("Summarize the timeline", "keep the 1936 date", ["Mara Voss"])).toEqual([]);
  });

  it("skips blank values and reports a repeated value once", () => {
    expect(
      replacedValueMentions("Mara Voss asked about Mara Voss", "", ["", " ", "Mara Voss", "mara voss"]),
    ).toEqual(["Mara Voss"]);
  });
});
