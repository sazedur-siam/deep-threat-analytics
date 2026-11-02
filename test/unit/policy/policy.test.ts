import { describe, expect, it } from 'vitest';
import { parseProjectConfig, type ProjectConfig } from '../../../src/config/projectConfig';
import type { EcosystemId, Finding } from '../../../src/core/types';
import { matchesGlob, matchesPackage, matchesVersion } from '../../../src/policy/glob';
import { evaluatePolicies } from '../../../src/policy/policy';
import { applySuppressions } from '../../../src/policy/suppress';

function finding(
  over: Partial<Finding> & { pkg?: string; eco?: EcosystemId; version?: string } = {},
): Finding {
  const { pkg = 'pkg', eco = 'npm', version = '1.0.0', ...rest } = over;
  return {
    id: 'a1b2c3d4e5f60718',
    ruleId: 'exec/node-child-process',
    title: 't',
    category: 'exec',
    severity: 'medium',
    message: 'm',
    source: 'code',
    package: { ecosystem: eco, name: pkg, version },
    ...rest,
  };
}

function config(yaml: string): ProjectConfig {
  const { config, errors } = parseProjectConfig(yaml);
  expect(errors).toEqual([]);
  return config;
}

describe('glob matching', () => {
  it.each([
    ['obfuscation/x', 'obfuscation/*', true],
    ['@scope/crypto-x', '*crypto*', true],
    ['exec/a', 'exec/?', true],
    ['exec/ab', 'exec/?', false],
    ['a.b', 'a.b', true],
    ['axb', 'a.b', false],
  ])('%s vs %s → %s', (value, glob, expected) => {
    expect(matchesGlob(value, glob)).toBe(expected);
  });

  it('matches packages with ecosystem prefixes and PyPI normalization', () => {
    expect(matchesPackage({ ecosystem: 'npm', name: 'lodash' }, 'lodash')).toBe(true);
    expect(matchesPackage({ ecosystem: 'npm', name: 'lodash' }, 'pypi:lodash')).toBe(false);
    expect(
      matchesPackage({ ecosystem: 'pypi', name: 'python-dateutil' }, 'pypi:Python_DateUtil'),
    ).toBe(true);
    expect(matchesPackage({ ecosystem: 'npm', name: '@types/node' }, '@types/*')).toBe(true);
    expect(matchesPackage({ ecosystem: 'npm', name: 'a' }, 'weird:a')).toBe(false);
  });

  it('matches versions with globs and x-ranges', () => {
    expect(matchesVersion('4.17.21', '4.x')).toBe(true);
    expect(matchesVersion('4.17.21', '4.17.x')).toBe(true);
    expect(matchesVersion('40.1.0', '4.x')).toBe(false);
    expect(matchesVersion('1.0.0', undefined)).toBe(true);
    expect(matchesVersion('1.0.0', '1.0.0')).toBe(true);
  });
});

describe('applySuppressions', () => {
  const cfg = config(`
allowlist: { packages: ['pypi:requests', '@types/*'], rules: [network/ip-lookup] }
ignore:
  - { package: lodash, rule: obfuscation/*, version: 4.x, reason: minified dist }
  - { package: left-pad }
  - { finding: 0123456789abcdef, reason: reviewed }
severityOverrides:
  - { rule: exec/*, package: build-*, severity: info }
  - { rule: exec/*, severity: low }
`);

  const cases: Array<[string, Partial<Parameters<typeof finding>[0]>, string | undefined]> = [
    ['allowlisted package', { pkg: 'requests', eco: 'pypi' }, 'allowlisted package'],
    ['prefix limits ecosystem', { pkg: 'requests', eco: 'npm' }, undefined],
    ['scoped glob', { pkg: '@types/node' }, 'allowlisted package'],
    ['allowlisted rule', { ruleId: 'network/ip-lookup' }, 'allowlisted rule'],
    [
      'ignore by package+rule+version',
      { pkg: 'lodash', ruleId: 'obfuscation/x', version: '4.17.21' },
      'minified dist',
    ],
    ['version mismatch', { pkg: 'lodash', ruleId: 'obfuscation/x', version: '5.0.0' }, undefined],
    ['rule mismatch', { pkg: 'lodash', ruleId: 'exec/x', version: '4.1.0' }, undefined],
    [
      'package-wide ignore',
      { pkg: 'left-pad', ruleId: 'anything/x' },
      'ignored in .depthreat/config.yaml',
    ],
    ['finding id', { id: '0123456789abcdef' }, 'reviewed'],
    ['nothing matches', {}, undefined],
  ];

  it.each(cases)('%s', (_name, over, reason) => {
    const [out] = applySuppressions([finding(over)], cfg);
    expect(out?.suppressed?.reason).toBe(reason);
  });

  it('applies inline manifest ignores per ecosystem', () => {
    const inline = new Map<string, string[] | 'all'>([
      ['npm:a', 'all'],
      ['npm:b', ['exec/*']],
      ['pypi:c', ['network/*']],
    ]);
    const out = applySuppressions(
      [
        finding({ pkg: 'a' }),
        finding({ pkg: 'b' }),
        finding({ pkg: 'b', ruleId: 'network/x' }),
        finding({ pkg: 'c', eco: 'pypi', ruleId: 'exec/x' }),
      ],
      config('{}'),
      inline,
    );
    expect(out.map((f) => f.suppressed?.reason)).toEqual([
      'ignored in manifest',
      'ignored in manifest',
      undefined,
      undefined,
    ]);
  });

  it('applies the first matching severity override without mutating input', () => {
    const input = [finding({ pkg: 'build-tool' }), finding(), finding({ ruleId: 'net/x' })];
    const out = applySuppressions(input, cfg);
    expect(out.map((f) => f.severity)).toEqual(['info', 'low', 'medium']);
    expect(input[0]?.severity).toBe('medium');
    expect(input[0]?.suppressed).toBeUndefined();
  });
});

describe('evaluatePolicies', () => {
  const policies = config(`
policies:
  - { name: no-hooks, deny: { category: install-hook } }
  - { name: no-net-crypto, packages: ['*crypto*'], deny: { category: [network, exfiltration] } }
  - { name: no-critical, deny: { minSeverity: critical } }
  - { name: vulns, deny: { source: osv, minSeverity: high }, action: warn }
  - { name: no-eval, deny: { rule: [dynamic-code/*] }, action: warn }
`).policies;

  const cases: Array<[string, Partial<Parameters<typeof finding>[0]>, string[]]> = [
    ['category', { category: 'install-hook' }, ['no-hooks']],
    ['package filter + category', { pkg: '@x/crypto-lib', category: 'network' }, ['no-net-crypto']],
    ['package filter excludes', { pkg: 'other', category: 'network' }, []],
    ['min severity', { severity: 'critical' }, ['no-critical']],
    ['source + severity', { source: 'osv', severity: 'high' }, ['vulns']],
    ['source but too low', { source: 'osv', severity: 'medium' }, []],
    ['rule glob', { ruleId: 'dynamic-code/eval-non-literal' }, ['no-eval']],
    ['multiple', { category: 'install-hook', severity: 'critical' }, ['no-hooks', 'no-critical']],
  ];

  it.each(cases)('%s', (_name, over, expected) => {
    const { findings } = evaluatePolicies([finding(over)], policies);
    expect(findings[0]?.policyViolations ?? []).toEqual(expected);
  });

  it('computes pass, warn and fail', () => {
    expect(evaluatePolicies([finding()], policies).status).toBe('pass');
    expect(evaluatePolicies([finding({ source: 'osv', severity: 'high' })], policies).status).toBe(
      'warn',
    );
    const result = evaluatePolicies(
      [finding({ source: 'osv', severity: 'high' }), finding({ category: 'install-hook' })],
      policies,
    );
    expect(result.status).toBe('fail');
    expect(result.violations.map((v) => [v.policy, v.action])).toEqual([
      ['vulns', 'warn'],
      ['no-hooks', 'error'],
    ]);
  });

  it('never lets suppressed findings violate policies', () => {
    const result = evaluatePolicies(
      [finding({ category: 'install-hook', suppressed: { reason: 'x' } })],
      policies,
    );
    expect(result.status).toBe('pass');
    expect(result.findings[0]?.policyViolations).toBeUndefined();
  });
});
