const IGNORE_MARKER = /depthreat-ignore(?:\[([^\]]*)\])?/;

/**
 * Parse an inline ignore marker from a comment: `depthreat-ignore` ignores every rule,
 * `depthreat-ignore[rule/a, obfuscation/*]` ignores the listed rule ids/globs.
 */
export function parseIgnoreMarker(comment: string): string[] | 'all' | undefined {
  const m = IGNORE_MARKER.exec(comment);
  if (!m) return undefined;
  if (m[1] === undefined) return 'all';
  const list = m[1]
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return list.length > 0 ? list : 'all';
}
