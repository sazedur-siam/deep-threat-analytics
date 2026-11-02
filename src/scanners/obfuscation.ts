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
};

interface Detection {
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  offset: number;
  length: number;
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
 * sink, obfuscator signatures, and escape-heavy strings. Plain minified code is not flagged.
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
      evidence: trimEvidence(text.slice(d.offset, d.offset + Math.min(d.length, 120))),
    };
  });
}
