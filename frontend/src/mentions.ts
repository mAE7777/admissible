/** Values slated for replacement that the user's own task or pinned facts mention. */
export function replacedValueMentions(taskText: string, pinsText: string, values: string[]): string[] {
  const haystack = `${taskText}\n${pinsText}`.toLowerCase();
  const seen = new Set<string>();
  const mentioned: string[] = [];
  for (const value of values) {
    const needle = value.trim();
    if (needle.length < 2) {
      continue;
    }
    const key = needle.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (haystack.includes(key)) {
      mentioned.push(needle);
    }
  }
  return mentioned;
}
