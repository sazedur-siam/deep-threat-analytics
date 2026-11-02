/** PEP 503 normalized project name: runs of `-`, `_`, `.` collapse to `-`, lowercased. */
export function normalizePythonName(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
}

/** Leading PEP 508 project name (letters, digits, `-`, `_`, `.`; starts/ends alphanumeric). */
export const PEP508_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/;

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

/** Extract the `==` pinned version from a specifier like `==1.2.3` or `>=1,==1.2.3`. */
export function pinnedVersion(spec: string): string | undefined {
  const m = /(?:^|,)\s*===?\s*([^\s,;*]+)\s*(?:,|$)/.exec(spec);
  return m?.[1];
}

export interface Requirement {
  name: string;
  extras: string[];
  /** Version specifier without parentheses, or `@ <url>` for direct references. */
  spec: string;
  marker?: string;
  /** Offset of the name within the parsed string. */
  nameStart: number;
  nameEnd: number;
}

/**
 * Parse one PEP 508 requirement string, e.g. `requests[socks] (>=2.0) ; python_version>"3.8"`.
 * Returns undefined when the string does not start with a valid project name.
 */
export function parseRequirement(text: string): Requirement | undefined {
  const lead = text.length - text.trimStart().length;
  const m = PEP508_NAME.exec(text.slice(lead));
  if (!m) return undefined;
  const nameStart = lead;
  const nameEnd = lead + m[0].length;
  let rest = text.slice(nameEnd);
  let marker: string | undefined;
  const semi = rest.indexOf(';');
  if (semi >= 0) {
    marker = rest.slice(semi + 1).trim() || undefined;
    rest = rest.slice(0, semi);
  }
  let extras: string[] = [];
  const ex = /^\s*\[([^\]]*)\]/.exec(rest);
  if (ex) {
    extras = (ex[1] as string)
      .split(',')
      .map((e) => e.trim())
      .filter(Boolean);
    rest = rest.slice(ex[0].length);
  }
  let spec = rest.trim();
  if (spec.startsWith('(') && spec.endsWith(')')) spec = spec.slice(1, -1).trim();
  return { name: m[0], extras, spec, ...(marker ? { marker } : {}), nameStart, nameEnd };
}
