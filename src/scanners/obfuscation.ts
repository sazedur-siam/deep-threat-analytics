import { makeFindingId, trimEvidence } from '../core/findings';
import { LineIndex } from '../core/text';
import type { Finding, Language, ResolvedDep, Severity } from '../core/types';

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const BASE64_BLOB = /["'`]([A-Za-z0-9+/]{200,}={0,2})["'`]/g;
const HEX_BLOB = /["'`]((?:[0-9a-fA-F]{2}){100,})["'`]/g;
const OBFUSCATOR_ID = /\b_0x[a-f0-9]{4,6}\b/g;
const FROM_CHAR_CODE = /String\.fromCharCode\s*\(/g;
const HEX_ESCAPES = /(?:\\x[0-9a-fA-F]{2}){40,}/;

/** Code that turns data back into running code. */
const EXEC_SINK: Record<string, RegExp> = {
  javascript: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\bvm\.(runIn\w*|Script)\b/,
  typescript: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\bvm\.(runIn\w*|Script)\b/,
  python: /\bexec\s*\(|\beval\s*\(|\bmarshal\.loads\s*\(|\bcompile\s*\(/,
  php: /\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\(/,
};

/** Fallback sink for languages without an EXEC_SINK entry (go, rust, java, shell). */
const GENERIC_SINK = /\beval\s*\(|\bFunction\s*\(|\bexec\s*\(/;

interface Detection {
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  offset: number;
  length: number;
  /** Overrides the default evidence (the matched text) when that text is not readable. */
  evidence?: string;
}

/** `U+FE00` style label for a code point. */
function codePointLabel(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** Format, private-use and variation-selector characters render as nothing or as a box. */
const UNREADABLE = /[\p{Cf}\p{Co}︀-️\u{E0100}-\u{E01EF}]/gu;

/** Replaces characters a reader cannot see with `<U+XXXX>` so evidence never carries them raw. */
export function escapeInvisible(text: string): string {
  return text.replace(UNREADABLE, (ch) => `<${codePointLabel(ch.codePointAt(0) as number)}>`);
}

// ---------------------------------------------------------------------------------------------
// Invisible-Unicode payloads (GlassWorm) and bidirectional controls (Trojan Source)
// ---------------------------------------------------------------------------------------------

const isVariationSelector = (cp: number) =>
  (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isPrivateUse = (cp: number) =>
  (cp >= 0xe000 && cp <= 0xf8ff) ||
  (cp >= 0xf0000 && cp <= 0xffffd) ||
  (cp >= 0x100000 && cp <= 0x10fffd);
/** ZWNJ / ZWJ: required for correct shaping of Persian, Arabic and Indic text. */
const isJoiner = (cp: number) => cp === 0x200c || cp === 0x200d;
/** Zero-width space, word joiner, invisible operators and BOM: no linguistic use mid-code. */
const isZeroWidth = (cp: number) =>
  cp === 0x200b || (cp >= 0x2060 && cp <= 0x2064) || cp === 0xfeff;

function isInvisibleCodePoint(cp: number): boolean {
  return (
    isVariationSelector(cp) || isTag(cp) || isPrivateUse(cp) || isJoiner(cp) || isZeroWidth(cp)
  );
}

/** Quick pre-check so files without any candidate character skip the per-code-point walk. */
const ANY_INVISIBLE =
  /[​-‍⁠-⁤﻿︀-️-\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}]/u;
const PICTOGRAPHIC = /\p{Extended_Pictographic}|\p{Emoji_Modifier}/u;
const isPictographic = (cp: number | undefined) =>
  cp !== undefined && PICTOGRAPHIC.test(String.fromCodePoint(cp));

/** Payload heuristics: one long run, or many characters spread over the file. */
const MIN_RUN = 10;
const MIN_TOTAL = 30;

interface InvisibleRun {
  /** UTF-16 offsets, end-exclusive. */
  start: number;
  end: number;
  cps: number[];
  /** Code point right before the run (undefined at file start). */
  before: number | undefined;
}

/** Collects maximal runs of consecutive invisible code points (iterating by code point). */
function invisibleRuns(text: string): InvisibleRun[] {
  const runs: InvisibleRun[] = [];
  let run: InvisibleRun | undefined;
  let prev: number | undefined;
  let cur: { cp: number; off: number } | undefined;

  const visit = (c: { cp: number; off: number }, before: number | undefined, after?: number) => {
    let invisible = isInvisibleCodePoint(c.cp);
    // A BOM at offset 0 is an encoding marker, not content.
    if (c.cp === 0xfeff && c.off === 0) invisible = false;
    // Emoji presentation selectors and ZWJ glue emoji together (❤️, 👨‍👩‍👧): they are
    // part of a visible glyph whenever they touch a pictographic code point.
    if (
      invisible &&
      (c.cp === 0xfe0e || c.cp === 0xfe0f || c.cp === 0x200d) &&
      (isPictographic(before) || isPictographic(after))
    ) {
      invisible = false;
    }
    if (!invisible) {
      run = undefined;
      return;
    }
    const width = c.cp > 0xffff ? 2 : 1;
    if (run) {
      run.cps.push(c.cp);
      run.end = c.off + width;
    } else {
      run = { start: c.off, end: c.off + width, cps: [c.cp], before };
      runs.push(run);
    }
  };

  let off = 0;
  for (const ch of text) {
    const next = { cp: ch.codePointAt(0) as number, off };
    off += ch.length;
    if (cur) visit(cur, prev, next.cp);
    prev = cur?.cp;
    cur = next;
  }
  if (cur) visit(cur, prev);
  return runs;
}

/**
 * Runs with a legitimate, visible purpose. A single character cannot carry a payload, so lone
 * variation selectors (CJK ideographic variants, keycaps like 1️⃣), lone joiners (Persian/Indic
 * text), lone private-use glyphs (icon fonts) and lone tags are ignored. Lone zero-width
 * spaces/word joiners still count, since scattering those is how text steganography works.
 * Tag sequences right after 🏴 are emoji subdivision flags (England, Scotland, Wales).
 */
function isBenignRun(run: InvisibleRun): boolean {
  const first = run.cps[0] as number;
  if (run.cps.length === 1) return !isZeroWidth(first);
  return run.before === 0x1f3f4 && run.cps.every(isTag) && run.cps[run.cps.length - 1] === 0xe007f;
}

/** Up to 30 code points of the same line before `offset`, escaped. */
function contextBefore(text: string, offset: number): string {
  const lineStart = text.lastIndexOf('\n', offset - 1) + 1;
  const tail = Array.from(text.slice(lineStart, offset)).slice(-30).join('');
  return escapeInvisible(trimEvidence(tail));
}

function describeRun(text: string, run: InvisibleRun): string {
  const shown = run.cps.slice(0, 6).map(codePointLabel).join(' ');
  const more = run.cps.length > 6 ? ' …' : '';
  return `"${contextBefore(text, run.start)}" + ${run.cps.length} invisible chars (${shown}${more})`;
}

function invisibleUnicodeDetections(text: string, sink: RegExp): Detection[] {
  if (!ANY_INVISIBLE.test(text)) return [];
  const runs = invisibleRuns(text).filter((r) => !isBenignRun(r));
  if (!runs.length) return [];
  const total = runs.reduce((n, r) => n + r.cps.length, 0);
  const longest = runs.reduce((a, b) => (b.cps.length > a.cps.length ? b : a));
  if (longest.cps.length < MIN_RUN && total < MIN_TOTAL) return [];

  const anchor = longest.cps.length >= MIN_RUN ? longest : (runs[0] as InvisibleRun);
  const executes = sink.test(text);
  const spread = runs.length > 1 ? ` (${total} in ${runs.length} places)` : '';
  return [
    {
      ruleId: 'obfuscation/invisible-unicode-payload',
      title: 'Hides data in invisible Unicode characters',
      severity: executes ? 'critical' : 'high',
      message:
        `hides ${total} invisible Unicode characters (variation selectors, private-use, tag or ` +
        `zero-width characters)${spread}, a GlassWorm-style hidden payload` +
        (executes ? ', next to code that executes dynamic code' : ''),
      offset: anchor.start,
      length: anchor.end - anchor.start,
      evidence:
        describeRun(text, anchor) + (runs.length > 1 ? `; ${total} invisible chars in total` : ''),
    },
  ];
}

function blobDetections(text: string, sink: RegExp | undefined): Detection[] {
  if (!sink || !sink.test(text)) return [];
  const out: Detection[] = [];
  for (const [re, kind, minEntropy] of [
    [BASE64_BLOB, 'base64', 4.5],
    [HEX_BLOB, 'hex', 3.5],
  ] as const) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const blob = m[1] as string;
      if (shannonEntropy(blob) < minEntropy) continue;
      out.push({
        ruleId: 'obfuscation/encoded-payload-exec',
        title: 'Executes an encoded payload',
        severity: 'high',
        message: `contains a ${blob.length}-character ${kind} payload and code that executes decoded data`,
        offset: m.index,
        length: Math.min(blob.length + 2, 200),
      });
      break;
    }
  }
  return out;
}

function countMatches(re: RegExp, text: string): { count: number; first: number } {
  re.lastIndex = 0;
  let count = 0;
  let first = -1;
  for (const m of text.matchAll(re)) {
    if (first < 0) first = m.index;
    count++;
  }
  return { count, first };
}

function jsDetections(text: string, sink: RegExp): Detection[] {
  const out: Detection[] = [];
  const ids = countMatches(OBFUSCATOR_ID, text);
  if (ids.count >= 20) {
    out.push({
      ruleId: 'obfuscation/js-obfuscator',
      title: 'Obfuscated with javascript-obfuscator',
      severity: sink.test(text) ? 'high' : 'medium',
      message: `uses ${ids.count} javascript-obfuscator style identifiers (_0x…)`,
      offset: ids.first,
      length: 8,
    });
  }
  const charCodes = countMatches(FROM_CHAR_CODE, text);
  if (charCodes.count >= 5) {
    out.push({
      ruleId: 'obfuscation/char-code-strings',
      title: 'Builds strings from character codes',
      severity: 'medium',
      message: `builds strings with String.fromCharCode ${charCodes.count} times`,
      offset: charCodes.first,
      length: 19,
    });
  }
  return out;
}

/**
 * Heuristics that regex rules cannot express: high-entropy payloads combined with an execution
 * sink, obfuscator signatures, escape-heavy strings, payloads hidden in invisible Unicode
 * characters and bidirectional control characters. Plain minified code is not flagged.
 */
export function detectObfuscation(
  filePath: string,
  relPath: string,
  text: string,
  dep: ResolvedDep,
  language: Language,
): Finding[] {
  const sink = EXEC_SINK[language];
  const detections = [...blobDetections(text, sink)];
  if (language === 'javascript' || language === 'typescript') {
    detections.push(...jsDetections(text, sink as RegExp));
  }
  const escapes = HEX_ESCAPES.exec(text);
  if (escapes && sink?.test(text)) {
    detections.push({
      ruleId: 'obfuscation/hex-escaped-strings',
      title: 'Hides strings with hex escapes',
      severity: 'medium',
      message: 'contains long \\x-escaped strings next to dynamic code execution',
      offset: escapes.index,
      length: Math.min(escapes[0].length, 200),
    });
  }
  if (language !== 'json') {
    detections.push(...invisibleUnicodeDetections(text, sink ?? GENERIC_SINK));
  }
  if (!detections.length) return [];

  const lines = new LineIndex(text);
  const pkg = { ecosystem: dep.ecosystem, name: dep.name, version: dep.version };
  return detections.map((d) => {
    const range = lines.range(d.offset, d.offset + d.length);
    return {
      id: makeFindingId(d.ruleId, pkg, relPath, range.startLine),
      ruleId: d.ruleId,
      title: d.title,
      category: 'obfuscation',
      severity: d.severity,
      message: `${dep.name} ${d.message} in ${relPath}`,
      source: 'code',
      package: pkg,
      location: { file: filePath, range },
      evidence:
        d.evidence ??
        escapeInvisible(trimEvidence(text.slice(d.offset, d.offset + Math.min(d.length, 120)))),
    };
  });
}
