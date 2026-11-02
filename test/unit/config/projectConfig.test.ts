import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  addAllowlistedPackage,
  addAllowlistedRule,
  addIgnore,
  defaultConfigTemplate,
  EMPTY_CONFIG,
  loadProjectConfig,
  parseProjectConfig,
} from '../../../src/config/projectConfig';

const FULL = `
allowlist:
  packages: [esbuild, '@types/*', 'pypi:requests']
  rules: [obfuscation/*]
ignore:
  - { package: lodash, rule: obfuscation/*, version: 4.x, reason: minified dist }
  - { finding: a1b2c3d4e5f60718, reason: reviewed }
  - { package: left-pad }
severityOverrides:
  - { rule: network/*, severity: low }
policies:
  - { name: no-install-hooks, deny: { category: install-hook }, action: error }
  - { name: no-net-crypto, packages: ['*crypto*'], deny: { category: [network, exfiltration] } }
  - { name: vulns, deny: { source: osv, minSeverity: high }, action: warn }
`;

describe('parseProjectConfig', () => {
  it('parses every section and normalizes single values to lists', () => {
    const { config, errors } = parseProjectConfig(FULL);
    expect(errors).toEqual([]);
    expect(config.allowlist).toEqual({
      packages: ['esbuild', '@types/*', 'pypi:requests'],
      rules: ['obfuscation/*'],
    });
    expect(config.ignore).toHaveLength(3);
    expect(config.severityOverrides).toEqual([{ rule: 'network/*', severity: 'low' }]);
    expect(config.policies[0]).toEqual({
      name: 'no-install-hooks',
      deny: { category: ['install-hook'] },
      action: 'error',
    });
    expect(config.policies[1]?.action).toBe('error');
    expect(config.policies[2]?.deny).toEqual({ source: ['osv'], minSeverity: 'high' });
  });

  it('treats empty documents as an empty config', () => {
    expect(parseProjectConfig('')).toEqual({ config: EMPTY_CONFIG, errors: [] });
    expect(parseProjectConfig('# only comments')).toEqual({ config: EMPTY_CONFIG, errors: [] });
    expect(parseProjectConfig(defaultConfigTemplate()).errors).toEqual([]);
  });

  it('keeps valid entries and reports invalid ones with paths', () => {
    const { config, errors } = parseProjectConfig(`
unknown: 1
allowlist: { packages: [1] }
ignore:
  - { package: ok }
  - { pakage: typo }
  - { finding: nothex }
severityOverrides: { rule: x }
policies:
  - { name: empty, deny: {} }
  - { name: bad-cat, deny: { category: nope } }
  - { name: good, deny: { rule: exec/* } }
`);
    expect(config.ignore).toEqual([{ package: 'ok' }]);
    expect(config.policies.map((p) => p.name)).toEqual(['good']);
    expect(config.allowlist).toEqual({ packages: [], rules: [] });
    const paths = errors.map((e) => e.path);
    expect(paths).toContain('unknown');
    expect(paths).toContain('allowlist.packages[0]');
    expect(paths.some((p) => p.startsWith('ignore[1]'))).toBe(true);
    expect(paths.some((p) => p.startsWith('ignore[2]'))).toBe(true);
    expect(paths).toContain('severityOverrides');
    expect(errors.find((e) => e.path.startsWith('policies[0]'))?.message).toMatch(/at least one/);
    expect(paths.some((p) => p.startsWith('policies[1].deny.category'))).toBe(true);
  });

  it('reports YAML syntax errors and non-mapping documents', () => {
    expect(parseProjectConfig('ignore: [').errors[0]?.path).toBe('');
    expect(parseProjectConfig('- a').errors[0]?.message).toMatch(/mapping/);
  });
});

describe('loadProjectConfig', () => {
  it('returns an empty config when the file is missing', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-cfg-'));
    expect(await loadProjectConfig(dir)).toEqual({ config: EMPTY_CONFIG, errors: [] });
  });

  it('loads config.yml as well', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-cfg-'));
    await mkdir(path.join(dir, '.depthreat'));
    await writeFile(path.join(dir, '.depthreat/config.yml'), 'allowlist: { rules: [a/b] }');
    const loaded = await loadProjectConfig(dir);
    expect(loaded.path).toBe(path.join(dir, '.depthreat/config.yml'));
    expect(loaded.config.allowlist.rules).toEqual(['a/b']);
  });
});

describe('config edit helpers', () => {
  const original = `# team config
allowlist:
  packages:
    - esbuild # build tool
ignore: []
`;

  it('adds entries while keeping comments', () => {
    let text = addAllowlistedPackage(original, '@types/*');
    text = addAllowlistedRule(text, 'network/ip-lookup');
    text = addIgnore(text, { package: 'lodash', rule: 'obfuscation/*', reason: 'minified' });
    expect(text).toContain('# team config');
    expect(text).toContain('# build tool');
    const { config, errors } = parseProjectConfig(text);
    expect(errors).toEqual([]);
    expect(config.allowlist.packages).toEqual(['esbuild', '@types/*']);
    expect(config.allowlist.rules).toEqual(['network/ip-lookup']);
    expect(config.ignore).toEqual([
      { package: 'lodash', rule: 'obfuscation/*', reason: 'minified' },
    ]);
  });

  it('is idempotent', () => {
    const once = addIgnore(original, { finding: 'a1b2c3d4e5f60718' });
    expect(addIgnore(once, { finding: 'a1b2c3d4e5f60718' })).toBe(once);
    expect(addAllowlistedPackage(original, 'esbuild')).toBe(original);
  });

  it('creates the file structure from nothing', () => {
    const text = addAllowlistedRule('', 'exec/x');
    expect(parseProjectConfig(text).config.allowlist.rules).toEqual(['exec/x']);
  });

  it('leaves the text alone when the target is not a list', () => {
    const odd = 'ignore:\n  nested: { value: 1 }\n';
    expect(parseProjectConfig(addIgnore(odd, { package: 'a' })).config.ignore).toEqual([]);
  });
});
