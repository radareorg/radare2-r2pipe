/** A JSON parser used by cmdj(). */
export type JsonParser = (text: string) => unknown;

/** Parse JSON while preserving integer literals outside JavaScript's safe range. */
export const parseJson: JsonParser = (text) => {
  // Validate before rewriting: quoting a number must never repair invalid JSON,
  // such as an unquoted object key. Keep the native result when no rewrite is needed.
  const parsed: unknown = JSON.parse(text);
  const integers: Array<{ start: number; end: number; literal: string }> = [];
  const tokens = /"(?:[^"\\]|\\[\s\S])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let match: RegExpExecArray | null;
  while ((match = tokens.exec(text)) !== null) {
    const token = match[0];
    if (token[0] !== '"' && /^-?(?:0|[1-9]\d*)$/.test(token) && !Number.isSafeInteger(Number(token))) {
      integers.push({ start: match.index, end: tokens.lastIndex, literal: token });
    }
  }
  if (integers.length === 0) {
    return parsed;
  }

  const strings = new Set<string>();
  tokens.lastIndex = 0;
  while ((match = tokens.exec(text)) !== null) {
    if (match[0][0] === '"') {
      strings.add(JSON.parse(match[0]));
    }
  }

  const replacements = new Map<string, bigint>();
  const parts: string[] = [];
  let previous = 0;
  for (const integer of integers) {
    let marker = `\0r2pipe.bigint:${replacements.size}`;
    // User strings, including escaped spellings of these markers, must stay strings.
    while (strings.has(marker) || replacements.has(marker)) {
      marker += ":";
    }
    replacements.set(marker, BigInt(integer.literal));
    parts.push(text.slice(previous, integer.start), JSON.stringify(marker));
    previous = integer.end;
  }
  parts.push(text.slice(previous));
  return JSON.parse(parts.join(""), (_key, value: unknown) =>
    typeof value === "string" && replacements.has(value) ? replacements.get(value) : value);
};
