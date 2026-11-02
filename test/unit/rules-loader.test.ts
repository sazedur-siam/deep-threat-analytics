import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { compileRule, hashRules, loadRules, parseRuleFile } from '../../src/rules/loader';

const BUILTIN = path.resolve(__dirname, '../../rules/builtin');

const validRule = `
- id: custom/test-rule
  title: Test
  category: network
  severity: low
  languages: ['*']
  match:
    any:
      - regex: 'fetch\\('
  message: '{package} fetches'
`;

describe('built-in rules', () => {
  it('all validate with no errors', async () => {
    const { rules, errors } = await loadRules([BUILTIN]);
    expect(errors).toEqual([]);
    expect(rules.length).toBeGreaterThan(0);
  });

  it('have unique ids and compile', async () => {
    const { rules } = await loadRules([BUILTIN]);
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
    for (const r of rules) expect(() => compileRule(r)).not.toThrow();
  });
});

describe('parseRuleFile', () => {
  it('applies defaults', () => {
    const { rules, errors } = parseRuleFile('x.yaml', validRule);
    expect(errors).toEqual([]);
    expect(rules[0]?.match.scope).toBe('line');
    expect(rules[0]?.enabled).toBe(true);
  });

  it('reports a readable error for a bad id and keeps valid siblings', () => {
    const text = `${validRule}
- id: Bad Id
  title: x
  category: network
  severity: low
  languages: ['*']
  match: { any: [{ regex: 'a' }] }
  message: m
`;
    const { rules, errors } = parseRuleFile('x.yaml', text);
    expect(rules).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ file: 'x.yaml', index: 1 });
    expect(errors[0]?.message).toContain('id');
  });

  it('rejects invalid regex, unknown category and missing match patterns', () => {
    const text = `
- id: a/b
  title: x
  category: nope
  severity: low
  languages: ['*']
  match: { any: [{ regex: '(' }] }
  message: m
- id: a/c
  title: x
  category: network
  severity: low
  languages: ['*']
  match: { scope: file }
  message: m
`;
    const { rules, errors } = parseRuleFile('x.yaml', text);
    expect(rules).toEqual([]);
    expect(errors[0]?.message).toMatch(/category/);
    expect(errors[0]?.message).toMatch(/invalid regular expression/);
    expect(errors[1]?.message).toMatch(/all.*any/);
  });

  it('rejects non-list documents and broken YAML', () => {
    expect(parseRuleFile('x.yaml', 'id: a/b').errors[0]?.message).toMatch(/list/);
    expect(parseRuleFile('x.yaml', '- [').errors[0]?.message).toMatch(/YAML/);
    expect(parseRuleFile('x.yaml', '')).toEqual({ rules: [], errors: [] });
  });
});

describe('loadRules', () => {
  it('lets user rules override and disable built-ins by id', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-rules-'));
    await writeFile(
      path.join(dir, 'override.yaml'),
      `
- id: exec/python-shell
  title: off
  category: exec
  severity: low
  languages: [python]
  match: { any: [{ regex: 'x' }] }
  message: m
  enabled: false
${validRule}`,
    );
    const builtin = await loadRules([BUILTIN]);
    const merged = await loadRules([BUILTIN, dir]);
    const ids = merged.rules.map((r) => r.id);
    expect(ids).not.toContain('exec/python-shell');
    expect(ids).toContain('custom/test-rule');
    expect(merged.hash).not.toBe(builtin.hash);
  });

  it('ignores missing directories', async () => {
    const result = await loadRules([path.join(tmpdir(), 'does-not-exist-depthreat')]);
    expect(result).toMatchObject({ rules: [], errors: [] });
  });
});

describe('hashRules', () => {
  it('is stable regardless of order', () => {
    const { rules } = parseRuleFile(
      'x.yaml',
      `${validRule}${validRule.replace('custom/test-rule', 'custom/other')}`,
    );
    expect(hashRules(rules)).toBe(hashRules([...rules].reverse()));
  });
});

describe('compileRule', () => {
  it('adds g and m flags and keeps user flags', () => {
    const { rules } = parseRuleFile(
      'x.yaml',
      `
- id: a/b
  title: t
  category: network
  severity: low
  languages: ['*']
  match: { any: [{ regex: 'FETCH', flags: i }] }
  message: m
`,
    );
    const compiled = compileRule(rules[0]!);
    expect(compiled.any[0]?.flags).toBe('gim');
    expect(compiled.all).toEqual([]);
  });
});
