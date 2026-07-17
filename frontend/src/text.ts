export const MAX_DOCUMENT_CODEPOINTS = 12_000;

export function codePointLength(value: string): number {
  return Array.from(value).length;
}

export function limitCodePoints(value: string, maximum = MAX_DOCUMENT_CODEPOINTS): string {
  const codePoints = Array.from(value);
  return codePoints.length <= maximum ? value : codePoints.slice(0, maximum).join("");
}
