import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { npmAdapter } from '../../../src/adapters/npm';
import type { Language, ResolvedDep } from '../../../src/core/types';
import { compileRule, parseRuleFile, type CompiledRule } from '../../../src/rules/loader';
import {
  MAX_FINDINGS_PER_RULE_PER_FILE,
  scanPackageCode,
  splitLines,
} from '../../../src/scanners/codeScanner';

const dep: ResolvedDep = {
  ecosystem: 'npm',
  name: 'pkg',
  version: '2.0.0',
  installPath: '/pkg',
  direct: true,
  isDev: false,
};

function rule(yaml: string): CompiledRule {
  const { rules, errors } = parseRuleFile('t.yaml', yaml);
  expect(errors).toEqual([]);
  return compileRule(rules[0]!);
}

const ruleWith = (match: string, extra = '') =>
  rule(`
- id: t/rule
  title: T
  category: network
  severity: medium
  languages: [javascript]
  message: '{package}@{version} hit in {file}'
${extra}
  match:
${match}
`);

async function scan(
  files: Record<string, string>,
  rules: CompiledRule[],
  opts: { language?: (f: string) => Language | undefined; maxFileSizeBytes?: number } = {},
) {
  return scanPackageCode({
    dep,
    files: Object.keys(files),
    languageOf: opts.language ?? (() => 'javascript'),
    rules,
    maxFileSizeBytes: opts.maxFileSizeBytes ?? 1e6,
    readFile: async (f) => {
      const text = files[f];
      if (text === undefined) throw new Error('missing');
      return text;
    },
  });
}

describe('splitLines', () => {
  it('handles LF and CRLF', () => {
    expect(splitLines('a\r\nb\nc')).toEqual(['a', 'b', 'c']);
  });
});

describe('scanPackageCode', () => {
  const lineRule = ruleWith(`    any: [{ regex: 'fetch\\(' }]\n    not: [{ regex: 'localhost' }]`);

  it('reports line matches with location, evidence and filled placeholders', async () => {
    const [f] = await scan({ '/pkg/lib/a.js': "const x = 1;\r\n  fetch('u');" }, [lineRule]);
    expect(f).toMatchObject({
      ruleId: 't/rule',
      source: 'code',
      message: 'pkg@2.0.0 hit in lib/a.js',
      package: { ecosystem: 'npm', name: 'pkg', version: '2.0.0' },
      location: {
        file: '/pkg/lib/a.js',
        range: { startLine: 1, startCol: 2, endLine: 1, endCol: 8 },
      },
      evidence: "fetch('u');",
    });
  });

  it('applies not-patterns per line', async () => {
    expect(await scan({ '/pkg/a.js': "fetch('http://localhost')" }, [lineRule])).toEqual([]);
  });

  it('skips comment-only lines', async () => {
    expect(await scan({ '/pkg/a.js': "// fetch('u')\n * fetch('u')" }, [lineRule])).toEqual([]);
  });

  it('caps findings per rule per file', async () => {
    const text = Array.from({ length: 20 }, () => 'fetch(1)').join('\n');
    const findings = await scan({ '/pkg/a.js': text }, [lineRule]);
    expect(findings).toHaveLength(MAX_FINDINGS_PER_RULE_PER_FILE);
  });

  it('requires every all-pattern on the same line for line scope', async () => {
    const r = ruleWith(`    all: [{ regex: 'a' }, { regex: 'b' }]`);
    expect(await scan({ '/pkg/x.js': 'a\nb' }, [r])).toEqual([]);
    expect(await scan({ '/pkg/x.js': 'a b' }, [r])).toHaveLength(1);
  });

  it('correlates patterns across lines for file scope', async () => {
    const r = ruleWith(
      `    all: [{ regex: 'readFile' }, { regex: 'fetch' }]\n    not: [{ regex: 'SAFE' }]\n    scope: file`,
    );
    const [f] = await scan({ '/pkg/x.js': 'x\nreadFile()\nfetch()' }, [r]);
    expect(f?.location?.range.startLine).toBe(1);
    expect(await scan({ '/pkg/x.js': 'readFile()\nfetch()\nSAFE' }, [r])).toEqual([]);
    expect(await scan({ '/pkg/x.js': 'readFile()', '/pkg/y.js': 'fetch()' }, [r])).toEqual([]);
  });

  it('correlates across files for package scope', async () => {
    const r = ruleWith(
      `    all: [{ regex: 'readFile' }]\n    any: [{ regex: 'fetch' }, { regex: 'axios' }]\n    scope: package`,
    );
    const findings = await scan({ '/pkg/x.js': 'readFile()', '/pkg/y.js': 'axios()' }, [r]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location?.file).toBe('/pkg/x.js');
    expect(await scan({ '/pkg/x.js': 'readFile()' }, [r])).toEqual([]);
  });

  it('filters by language and file glob', async () => {
    const py = rule(`
- id: t/py
  title: T
  category: exec
  severity: low
  languages: [python]
  files: ['setup.py']
  match: { any: [{ regex: 'os' }] }
  message: m
`);
    const language = (f: string): Language => (f.endsWith('.py') ? 'python' : 'javascript');
    const findings = await scan(
      { '/pkg/setup.py': 'os', '/pkg/other.py': 'os', '/pkg/a.js': 'os' },
      [py],
      { language },
    );
    expect(findings.map((f) => f.location?.file)).toEqual(['/pkg/setup.py']);
  });

  it('does not apply wildcard-language rules to JSON manifests', async () => {
    const any = rule(`
- id: t/any
  title: T
  category: network
  severity: low
  languages: ['*']
  match: { any: [{ regex: 'x' }] }
  message: m
`);
    const language = (f: string): Language => (f.endsWith('.json') ? 'json' : 'javascript');
    const findings = await scan({ '/pkg/package.json': 'x', '/pkg/a.js': 'x' }, [any], {
      language,
    });
    expect(findings.map((f) => f.location?.file)).toEqual(['/pkg/a.js']);
  });

  it('skips unknown languages, binary, oversized and unreadable files', async () => {
    const files = {
      '/pkg/a.bin': 'fetch(1)',
      '/pkg/b.js': 'fetch(1)\0',
      '/pkg/c.js': `fetch(1)${' '.repeat(100)}`,
      '/pkg/d.js': 'fetch(1)',
    };
    const findings = await scanPackageCode({
      dep,
      files: [...Object.keys(files), '/pkg/missing.js'],
      languageOf: (f) => (f.endsWith('.js') ? 'javascript' : undefined),
      rules: [lineRule],
      maxFileSizeBytes: 50,
      readFile: async (f) => {
        const text = files[f as keyof typeof files];
        if (text === undefined) throw new Error('missing');
        return text;
      },
    });
    expect(findings.map((f) => f.location?.file)).toEqual(['/pkg/d.js']);
  });

  it('trims evidence on very long minified lines and keeps the right column', async () => {
    const line = `${'a'.repeat(5000)}fetch(1)${'b'.repeat(5000)}`;
    const [f] = await scan({ '/pkg/min.js': line }, [lineRule]);
    expect(f?.location?.range.startCol).toBe(5000);
    expect(f?.evidence?.length).toBeLessThanOrEqual(200);
    expect(f?.evidence).toContain('fetch(1)');
  });

  it('produces stable ids and sorted output', async () => {
    const files = { '/pkg/b.js': 'fetch(1)', '/pkg/a.js': 'x\nfetch(1)' };
    const one = await scan(files, [lineRule]);
    const two = await scan(files, [lineRule]);
    expect(one.map((f) => f.id)).toEqual(two.map((f) => f.id));
    expect(one.map((f) => f.location?.file)).toEqual(['/pkg/a.js', '/pkg/b.js']);
    expect(new Set(one.map((f) => f.id)).size).toBe(2);
  });

  it('can turn obfuscation heuristics off', async () => {
    const blob = 'QmFzZTY0'.repeat(10) + 'x9Kq2Lm7Zp4Rt8Vw1Yb3Nc6Hd5Jf0Gs'.repeat(8);
    const files = { '/pkg/o.js': `eval(Buffer.from("${blob}", "base64").toString())` };
    const base = { dep, files: ['/pkg/o.js'], languageOf: () => 'javascript' as const, rules: [] };
    const read = async () => files['/pkg/o.js'];
    const on = await scanPackageCode({ ...base, maxFileSizeBytes: 1e6, readFile: read });
    const off = await scanPackageCode({
      ...base,
      maxFileSizeBytes: 1e6,
      readFile: read,
      obfuscation: false,
    });
    expect(on.map((f) => f.ruleId)).toContain('obfuscation/encoded-payload-exec');
    expect(off).toEqual([]);
  });

  it('stops when aborted', async () => {
    await expect(
      scanPackageCode({
        dep,
        files: ['/pkg/a.js'],
        languageOf: () => 'javascript',
        rules: [lineRule],
        maxFileSizeBytes: 1e6,
        signal: AbortSignal.abort(),
        readFile: async () => 'fetch(1)',
      }),
    ).rejects.toThrow();
  });

  it('reads from disk by default', async () => {
    const root = path.resolve(__dirname, '../../fixtures/npm-sample/node_modules/clean-utils');
    const findings = await scanPackageCode({
      dep: { ...dep, installPath: root },
      files: [path.join(root, 'index.js')],
      languageOf: npmAdapter.languageOf,
      rules: [ruleWith(`    any: [{ regex: 'capitalize' }]`)],
      maxFileSizeBytes: 1e6,
    });
    expect(findings[0]?.message).toBe('pkg@2.0.0 hit in index.js');
  });
});
