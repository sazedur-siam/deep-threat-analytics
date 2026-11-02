import { readFile as fsReadFile } from 'node:fs/promises';
import * as path from 'node:path';
import picomatch from 'picomatch';
import { makeFindingId, trimEvidence } from '../core/findings';
import type { Finding, Language, ResolvedDep } from '../core/types';
import type { CompiledRule } from '../rules/loader';
import { detectObfuscation } from './obfuscation';

/** Max findings per rule per file, so one noisy pattern cannot flood the results. */
export const MAX_FINDINGS_PER_RULE_PER_FILE = 5;

export interface CodeScanInput {
  dep: ResolvedDep;
  /** Absolute paths, already filtered and capped by the adapter. */
  files: string[];
  languageOf: (file: string) => Language | undefined;
  rules: CompiledRule[];
  maxFileSizeBytes: number;
  /** Run heuristic obfuscation detection (default true). */
  obfuscation?: boolean;
  signal?: AbortSignal;
  readFile?: (file: string) => Promise<string>;
}

interface Hit {
  line: number;
  col: number;
  length: number;
}

interface SourceFile {
  path: string;
  rel: string;
  language: Language;
  text: string;
  /** Lines with comment-only lines blanked, so rules don't fire on docs/examples. */
  lines: string[];
}

const COMMENT_LINE = /^\s*(\/\/|#|\*|\/\*|<!--)/;

export function splitLines(text: string): string[] {
  return text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

function firstHit(re: RegExp, line: string): { col: number; length: number } | undefined {
  re.lastIndex = 0;
  const m = re.exec(line);
  return m ? { col: m.index, length: Math.max(1, m[0].length) } : undefined;
}

/** First hit of `re` anywhere in the file. */
function findInFile(re: RegExp, file: SourceFile): Hit | undefined {
  for (let i = 0; i < file.lines.length; i++) {
    const hit = firstHit(re, file.lines[i] as string);
    if (hit) return { line: i, ...hit };
  }
  return undefined;
}

function evidence(line: string, col: number): string {
  return trimEvidence(line.slice(Math.max(0, col - 80), col + 120));
}

function appliesTo(rule: CompiledRule, file: SourceFile): boolean {
  const { languages, files } = rule.rule;
  const languageOk =
    languages.includes(file.language) || (languages.includes('*') && file.language !== 'json');
  if (!languageOk) return false;
  return !files || picomatch.isMatch(path.basename(file.path), files, { dot: true });
}

function makeFinding(rule: CompiledRule, dep: ResolvedDep, file: SourceFile, hit: Hit): Finding {
  const r = rule.rule;
  const pkg = { ecosystem: dep.ecosystem, name: dep.name, version: dep.version };
  const message = r.message
    .replaceAll('{package}', dep.name)
    .replaceAll('{version}', dep.version)
    .replaceAll('{file}', file.rel);
  return {
    id: makeFindingId(r.id, pkg, file.rel, hit.line),
    ruleId: r.id,
    title: r.title,
    category: r.category,
    severity: r.severity,
    message,
    source: 'code',
    package: pkg,
    location: {
      file: file.path,
      range: {
        startLine: hit.line,
        startCol: hit.col,
        endLine: hit.line,
        endCol: hit.col + hit.length,
      },
    },
    evidence: evidence(file.lines[hit.line] ?? '', hit.col),
    ...(r.references ? { references: r.references } : {}),
  };
}

function scanLines(rule: CompiledRule, dep: ResolvedDep, file: SourceFile): Finding[] {
  const out: Finding[] = [];
  for (let i = 0; i < file.lines.length && out.length < MAX_FINDINGS_PER_RULE_PER_FILE; i++) {
    const line = file.lines[i] as string;
    if (!line) continue;
    let hit: { col: number; length: number } | undefined;
    let ok = true;
    for (const re of rule.all) {
      const h = firstHit(re, line);
      if (!h) {
        ok = false;
        break;
      }
      hit ??= h;
    }
    if (!ok) continue;
    if (rule.any.length) {
      const h = rule.any.map((re) => firstHit(re, line)).find((x) => x !== undefined);
      if (!h) continue;
      hit ??= h;
    }
    if (!hit || rule.not.some((re) => firstHit(re, line))) continue;
    out.push(makeFinding(rule, dep, file, { line: i, ...hit }));
  }
  return out;
}

/** Evaluate all/any/not over a set of files; returns the anchor hit when the rule fires. */
function matchAcross(
  rule: CompiledRule,
  files: SourceFile[],
): { file: SourceFile; hit: Hit } | undefined {
  const locate = (re: RegExp) => {
    for (const file of files) {
      const hit = findInFile(re, file);
      if (hit) return { file, hit };
    }
    return undefined;
  };
  let anchor: { file: SourceFile; hit: Hit } | undefined;
  for (const re of rule.all) {
    const found = locate(re);
    if (!found) return undefined;
    anchor ??= found;
  }
  if (rule.any.length) {
    const found = rule.any.map(locate).find((x) => x !== undefined);
    if (!found) return undefined;
    anchor ??= found;
  }
  if (!anchor || rule.not.some((re) => locate(re))) return undefined;
  return anchor;
}

async function loadFile(
  file: string,
  input: CodeScanInput,
  read: (f: string) => Promise<string>,
): Promise<SourceFile | undefined> {
  const language = input.languageOf(file);
  if (!language) return undefined;
  let text: string;
  try {
    text = await read(file);
  } catch {
    return undefined;
  }
  if (text.length > input.maxFileSizeBytes || text.includes('\0')) return undefined;
  const lines = splitLines(text).map((l) => (COMMENT_LINE.test(l) ? '' : l));
  const rel = input.dep.installPath ? path.relative(input.dep.installPath, file) : file;
  return { path: file, rel: rel.split(path.sep).join('/'), language, text, lines };
}

/**
 * Apply detection rules (and obfuscation heuristics) to one package's files. Never executes
 * anything; only reads files. Output is sorted by file, line and rule id.
 */
export async function scanPackageCode(input: CodeScanInput): Promise<Finding[]> {
  const read = input.readFile ?? ((f: string) => fsReadFile(f, 'utf8'));
  const findings: Finding[] = [];
  const loaded: SourceFile[] = [];
  for (const file of input.files) {
    input.signal?.throwIfAborted();
    const source = await loadFile(file, input, read);
    if (source) loaded.push(source);
  }

  for (const file of loaded) {
    input.signal?.throwIfAborted();
    for (const rule of input.rules) {
      if (!appliesTo(rule, file)) continue;
      if (rule.rule.match.scope === 'line') findings.push(...scanLines(rule, input.dep, file));
      else if (rule.rule.match.scope === 'file') {
        const m = matchAcross(rule, [file]);
        if (m) findings.push(makeFinding(rule, input.dep, m.file, m.hit));
      }
    }
    if (input.obfuscation !== false) {
      findings.push(...detectObfuscation(file.path, file.rel, file.text, input.dep, file.language));
    }
  }

  for (const rule of input.rules) {
    if (rule.rule.match.scope !== 'package') continue;
    const files = loaded.filter((f) => appliesTo(rule, f));
    const m = matchAcross(rule, files);
    if (m) findings.push(makeFinding(rule, input.dep, m.file, m.hit));
  }

  return findings.sort(
    (a, b) =>
      (a.location?.file ?? '').localeCompare(b.location?.file ?? '') ||
      (a.location?.range.startLine ?? 0) - (b.location?.range.startLine ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}
