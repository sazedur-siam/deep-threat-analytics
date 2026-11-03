import { readdirSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { Language, ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules, type CompiledRule } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';

/**
 * Positive and negative cases for every built-in rule live in rule-cases/*.json (one file per
 * rule pack), so new rule packs add a file instead of editing this harness. Every snippet is an
 * inert string that is only pattern-matched, never executed.
 *
 * Format: { "<rule id>": { "lang": "js", "pos": [...], "neg": [...], "also": [["py", "..."]] } }
 * A file may also contain { "<existing id>": { "also": [...] } } to add positives in other
 * languages for a rule defined elsewhere.
 */
const LANGUAGE = {
  js: 'javascript',
  py: 'python',
  go: 'go',
  rs: 'rust',
  php: 'php',
  java: 'java',
  sh: 'shell',
} as const satisfies Record<string, Language>;
type Lang = keyof typeof LANGUAGE;

interface Case {
  lang: Lang;
  pos: string[];
  neg: string[];
  also: Array<[Lang, string]>;
}

const CASES_DIR = path.join(__dirname, 'rule-cases');

function loadCases(): Record<string, Case> {
  const cases: Record<string, Case> = {};
  const extras: Array<[string, Array<[Lang, string]>]> = [];
  for (const file of readdirSync(CASES_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()) {
    const doc = JSON.parse(readFileSync(path.join(CASES_DIR, file), 'utf8')) as Record<
      string,
      Partial<Case>
    >;
    for (const [id, c] of Object.entries(doc)) {
      if (c.lang === undefined) {
        extras.push([id, c.also ?? []]);
        continue;
      }
      if (cases[id]) throw new Error(`${file}: cases for ${id} are already defined`);
      if (!LANGUAGE[c.lang]) throw new Error(`${file}: unknown lang "${c.lang}" for ${id}`);
      cases[id] = { lang: c.lang, pos: c.pos ?? [], neg: c.neg ?? [], also: c.also ?? [] };
    }
  }
  for (const [id, also] of extras) {
    if (!cases[id]) throw new Error(`extra positives for ${id}, which has no cases`);
    cases[id].also.push(...also);
  }
  return cases;
}

const CASES = loadCases();

const dep: ResolvedDep = {
  ecosystem: 'npm',
  name: 'fixture-pkg',
  version: '1.0.0',
  installPath: '/pkg',
  direct: true,
  isDev: false,
};

let rules: CompiledRule[] = [];

beforeAll(async () => {
  const loaded = await loadRules([path.resolve(__dirname, '../../../rules/builtin')]);
  rules = loaded.rules.map(compileRule);
});

async function ruleIdsFor(lang: Lang, code: string): Promise<string[]> {
  const findings = await scanPackageCode({
    dep,
    files: [`/pkg/sample.${lang}`],
    languageOf: () => LANGUAGE[lang],
    rules,
    maxFileSizeBytes: 1e6,
    obfuscation: false,
    readFile: async () => code,
  });
  return findings.map((f) => f.ruleId);
}

const lastLine = (code: string) => code.split('\n').at(-1);

describe('built-in rules', () => {
  it('every built-in rule has positive and negative cases', () => {
    expect(Object.keys(CASES).sort()).toEqual(rules.map((r) => r.rule.id).sort());
    for (const [id, c] of Object.entries(CASES)) {
      expect(c.pos.length, id).toBeGreaterThan(0);
      expect(c.neg.length, id).toBeGreaterThan(0);
    }
  });

  for (const [id, c] of Object.entries(CASES)) {
    describe(id, () => {
      for (const code of c.pos) {
        it(`matches: ${lastLine(code)}`, async () => {
          expect(await ruleIdsFor(c.lang, code)).toContain(id);
        });
      }
      for (const code of c.neg) {
        it(`ignores: ${lastLine(code)}`, async () => {
          expect(await ruleIdsFor(c.lang, code)).not.toContain(id);
        });
      }
      for (const [lang, code] of c.also) {
        it(`matches ${lang}: ${lastLine(code)}`, async () => {
          expect(await ruleIdsFor(lang, code)).toContain(id);
        });
      }
      it('ignores the positive case when it is commented out', async () => {
        const prefix = c.lang === 'py' || c.lang === 'sh' ? '#' : '//';
        const commented = c.pos[0]!.split('\n')
          .map((l) => `${prefix} ${l}`)
          .join('\n');
        expect(await ruleIdsFor(c.lang, commented)).not.toContain(id);
      });
    });
  }
});
