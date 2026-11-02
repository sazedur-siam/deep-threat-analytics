import * as path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { splitLines } from '../../core/text';
import type { DeclaredDep } from '../../core/types';
import { normalizePythonName, parseIgnoreMarker, parseRequirement } from './names';

const DEV_REQUIREMENTS =
  /^(requirements[-_.]?(dev|test|tests|lint|docs)|(dev|test|tests)[-_]requirements)\b/i;
const DEV_GROUPS = new Set(['dev', 'test', 'tests', 'lint', 'docs', 'typing']);

/** Split `code  # comment` on the first `#` that starts a comment (line start or after space). */
function splitComment(line: string): { code: string; comment: string } {
  const m = /(^|\s)#/.exec(line);
  if (!m) return { code: line, comment: '' };
  const at = m.index + m[1]!.length;
  return { code: line.slice(0, at), comment: line.slice(at + 1) };
}

function dep(
  manifestPath: string,
  rawName: string,
  versionSpec: string,
  line: number,
  col: number,
  isDev: boolean,
  comment: string,
): DeclaredDep {
  const ignored = parseIgnoreMarker(comment);
  return {
    ecosystem: 'pypi',
    name: normalizePythonName(rawName),
    versionSpec,
    manifestPath,
    range: { startLine: line, startCol: col, endLine: line, endCol: col + rawName.length },
    isDev,
    ...(ignored ? { ignoredRules: ignored } : {}),
  };
}

/** requirements*.txt: one PEP 508 requirement per (possibly continued) line. */
export function parseRequirementsTxt(manifestPath: string, text: string): DeclaredDep[] {
  const isDev = DEV_REQUIREMENTS.test(path.basename(manifestPath));
  const lines = splitLines(text);
  const out: DeclaredDep[] = [];
  for (let i = 0; i < lines.length; i++) {
    const startLine = i;
    let { code, comment } = splitComment(lines[i] as string);
    // Backslash continuations join the next physical line.
    while (/\\\s*$/.test(code) && i + 1 < lines.length) {
      i++;
      const next = splitComment(lines[i] as string);
      code = code.replace(/\\\s*$/, ' ') + next.code;
      comment ||= next.comment;
    }
    const trimmed = code.trim();
    if (!trimmed || trimmed.startsWith('-') || /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) continue;
    if (/^[./~]/.test(trimmed)) continue;
    const req = parseRequirement(code);
    if (!req) continue;
    out.push(dep(manifestPath, req.name, req.spec, startLine, req.nameStart, isDev, comment));
  }
  return out;
}

/** Quoted strings on a line with their start columns (TOML basic and literal strings). */
function quotedStrings(line: string): Array<{ value: string; col: number }> {
  const out: Array<{ value: string; col: number }> = [];
  for (const m of line.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)) {
    out.push({ value: (m[1] ?? m[2]) as string, col: m.index + 1 });
  }
  return out;
}

function arrayContext(table: string, key: string): { isDev: boolean } | undefined {
  if (table === 'project' && key === 'dependencies') return { isDev: false };
  if (table === 'project.optional-dependencies') return { isDev: false };
  if (table === 'dependency-groups') return { isDev: true };
  return undefined;
}

function poetryTable(table: string): { isDev: boolean } | undefined {
  if (table === 'tool.poetry.dependencies') return { isDev: false };
  if (table === 'tool.poetry.dev-dependencies') return { isDev: true };
  const group = /^tool\.poetry\.group\.([^.]+)\.dependencies$/.exec(table);
  return group ? { isDev: DEV_GROUPS.has(group[1] as string) } : undefined;
}

function unquoteKey(key: string): string {
  return key.replace(/^["']|["']$/g, '');
}

function poetrySpec(value: string): string {
  const str = /^\s*["']([^"']*)["']/.exec(value);
  if (str) return str[1] as string;
  return /version\s*=\s*["']([^"']*)["']/.exec(value)?.[1] ?? '';
}

/** pyproject.toml: PEP 621, PEP 735 dependency groups and Poetry dependency tables. */
export function parsePyproject(manifestPath: string, text: string): DeclaredDep[] {
  try {
    parseToml(text);
  } catch {
    return [];
  }
  const out: DeclaredDep[] = [];
  const lines = splitLines(text);
  let table = '';
  let array: { isDev: boolean } | undefined;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    const { code, comment } = splitComment(raw);
    const header = /^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*$/.exec(code);
    if (header) {
      table = (header[1] as string).replace(/\s*\.\s*/g, '.').replace(/"/g, '');
      array = undefined;
      // [tool.poetry.dependencies.requests] style sub-table.
      const sub = /^(.*)\.([^.]+)$/.exec(table);
      const ctx = sub ? poetryTable(sub[1] as string) : undefined;
      if (sub && ctx && sub[2] !== 'python') {
        const name = sub[2] as string;
        out.push(dep(manifestPath, name, '', i, raw.indexOf(name), ctx.isDev, comment));
      }
      continue;
    }
    if (array) {
      for (const s of quotedStrings(code)) {
        const req = parseRequirement(s.value);
        if (req) {
          const col = s.col + req.nameStart;
          out.push(dep(manifestPath, req.name, req.spec, i, col, array.isDev, comment));
        }
      }
      if (/\]/.test(code.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, ''))) array = undefined;
      continue;
    }
    const kv = /^\s*("[^"]+"|'[^']+'|[A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(code);
    if (!kv) continue;
    const key = unquoteKey(kv[1] as string);
    const value = kv[2] as string;
    const ctx = arrayContext(table, key);
    if (ctx && value.trimStart().startsWith('[')) {
      const valueCol = code.length - value.length;
      for (const s of quotedStrings(value)) {
        const req = parseRequirement(s.value);
        if (req) {
          const col = valueCol + s.col + req.nameStart;
          out.push(dep(manifestPath, req.name, req.spec, i, col, ctx.isDev, comment));
        }
      }
      if (!/\]\s*$/.test(value.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '').trimEnd())) array = ctx;
      continue;
    }
    const poetry = poetryTable(table);
    if (poetry && key !== 'python') {
      const col = raw.indexOf(key);
      out.push(dep(manifestPath, key, poetrySpec(value), i, col, poetry.isDev, comment));
    }
  }
  return out;
}
