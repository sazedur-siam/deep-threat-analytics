import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { EcosystemAdapter } from '../../src/adapters/adapter';
import { npmAdapter } from '../../src/adapters/npm';
import { pythonAdapter } from '../../src/adapters/python';
import { EMPTY_CONFIG, parseProjectConfig } from '../../src/config/projectConfig';
import { DEFAULT_SETTINGS, type DepThreatSettings } from '../../src/config/settings';
import { ScanCache } from '../../src/core/cache';
import { scanManifests, type EngineOptions } from '../../src/core/engine';
import type { Finding } from '../../src/core/types';
import { compileRule, loadRules, type CompiledRule } from '../../src/rules/loader';

const FIXTURES = path.resolve(__dirname, '../fixtures');
const NPM = path.join(FIXTURES, 'npm-sample/package.json');
const PY = path.join(FIXTURES, 'py-sample/requirements.txt');

let rules: CompiledRule[];
let rulesHash: string;

beforeAll(async () => {
  const loaded = await loadRules([path.resolve(__dirname, '../../rules/builtin')]);
  rules = loaded.rules.map(compileRule);
  rulesHash = loaded.hash;
});

function options(over: Partial<EngineOptions> = {}, settings: Partial<DepThreatSettings> = {}) {
  return {
    adapters: [npmAdapter, pythonAdapter],
    rules,
    rulesHash,
    settings: { ...DEFAULT_SETTINGS, online: { ...DEFAULT_SETTINGS.online }, ...settings },
    projectConfig: EMPTY_CONFIG,
    trusted: false,
    ...over,
  } as EngineOptions;
}

const active = (findings: Finding[]) => findings.filter((f) => !f.suppressed);
const idsFor = (findings: Finding[], pkg: string) =>
  findings
    .filter((f) => f.package.name === pkg)
    .map((f) => f.ruleId)
    .sort();

describe('scanManifests', () => {
  it('scans npm and Python manifests together', async () => {
    const result = await scanManifests([NPM, PY, '/elsewhere/Cargo.toml'], options());
    expect(result.manifests.map((m) => m.ecosystem)).toEqual(['npm', 'pypi']);
    expect(result.errors).toEqual([]);
    expect(idsFor(result.findings, 'evil-env-stealer')).toContain('exfiltration/env-to-network');
    expect(idsFor(result.findings, 'evil-exfil')).toContain('exfiltration/python-env-to-network');
    expect(result.stats).toMatchObject({ cached: 0 });
    expect(result.stats.scanned).toBe(result.stats.packages - 2); // two deps are not installed
    expect(result.status).toBe('pass');
  });

  it('applies inline manifest ignores', async () => {
    const result = await scanManifests([PY], options());
    const shell = result.findings.filter((f) => f.ruleId === 'exec/python-shell');
    expect(shell.length).toBeGreaterThan(0);
    expect(shell.every((f) => f.suppressed?.reason === 'ignored in manifest')).toBe(true);
    expect(idsFor(active(result.findings), 'evil-setup')).toEqual(['install-hook/python-pth-exec']);
  });

  it('applies project config suppressions and policies', async () => {
    const { config } = parseProjectConfig(`
allowlist: { packages: [evil-env-stealer] }
policies:
  - { name: no-install-hooks, deny: { category: install-hook } }
`);
    const result = await scanManifests([NPM], options({ projectConfig: config }));
    expect(active(result.findings).some((f) => f.package.name === 'evil-env-stealer')).toBe(false);
    expect(result.status).toBe('fail');
    expect(result.violations.map((v) => [v.policy, v.package.name])).toEqual([
      ['no-install-hooks', 'evil-postinstall'],
    ]);
  });

  it('reuses cached results until the rules change', async () => {
    const file = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-engine-')), 'c.json');
    const spy = vi.spyOn(npmAdapter, 'listSourceFiles');
    const cache = new ScanCache(file);
    const first = await scanManifests([NPM], options({ cache }));
    const calls = spy.mock.calls.length;
    expect(calls).toBeGreaterThan(0);

    const reloaded = new ScanCache(file);
    await reloaded.load();
    const second = await scanManifests([NPM], options({ cache: reloaded }));
    expect(spy.mock.calls.length).toBe(calls);
    expect(second.stats.cached).toBe(first.stats.scanned);
    expect(second.findings.map((f) => f.id)).toEqual(first.findings.map((f) => f.id));

    await scanManifests([NPM], options({ cache: reloaded, rulesHash: 'changed' }));
    expect(spy.mock.calls.length).toBe(calls * 2);
    spy.mockRestore();
  });

  it('runs online checks with every resolved package and reports their errors', async () => {
    const check = vi.fn(async (deps) => ({
      findings: [
        {
          id: '0000000000000001',
          ruleId: 'vulnerability/ghsa-test',
          title: 'GHSA-test',
          category: 'vulnerability',
          severity: 'high',
          message: 'm',
          source: 'osv',
          package: { ecosystem: 'npm', name: 'not-installed', version: '4.2.1' },
        } as Finding,
      ],
      errors: deps.length ? ['OSV lookup failed for 1 package'] : [],
    }));
    const result = await scanManifests([NPM], options({ online: [check] }));
    const names = check.mock.calls[0]![0].map((d: { name: string }) => d.name);
    expect(names).toContain('not-installed');
    expect(result.findings.some((f) => f.ruleId === 'vulnerability/ghsa-test')).toBe(true);
    expect(result.errors).toEqual(['OSV lookup failed for 1 package']);
  });

  it('reports unreadable manifests without failing the scan', async () => {
    const result = await scanManifests(
      [path.join(FIXTURES, 'missing/package.json'), NPM],
      options(),
    );
    expect(result.errors[0]).toMatch(/^Could not analyze .*missing/);
    expect(result.manifests[0]?.error).toBeDefined();
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('dedupes packages shared by several manifests', async () => {
    const onProgress = vi.fn();
    const result = await scanManifests([NPM, NPM], options({ onProgress }));
    const single = await scanManifests([NPM], options());
    expect(result.stats.packages).toBe(single.stats.packages);
    expect(result.findings).toHaveLength(single.findings.length);
    const phases = new Set(onProgress.mock.calls.map((c) => c[0].phase));
    expect(phases).toEqual(new Set(['resolve', 'scan']));
  });

  it('honors dev and transitive settings', async () => {
    const withDev = await scanManifests([NPM], options({}, { includeDevDependencies: true }));
    expect(withDev.manifests[0]?.deps.some((d) => d.name === 'dev-only-tool')).toBe(true);
    const direct = await scanManifests([NPM], options({}, { scanTransitive: false }));
    expect(direct.manifests[0]?.deps.some((d) => d.name === 'tiny-dep')).toBe(false);
  });

  it('stops when cancelled', async () => {
    await expect(scanManifests([NPM], options({ signal: AbortSignal.abort() }))).rejects.toThrow();
    const ctrl = new AbortController();
    const failing: EcosystemAdapter = {
      ...npmAdapter,
      resolve: async () => {
        ctrl.abort();
        throw new Error('aborted mid-resolve');
      },
    };
    await expect(
      scanManifests([NPM], options({ adapters: [failing], signal: ctrl.signal })),
    ).rejects.toThrow('aborted mid-resolve');
  });

  it('reports cache write failures as errors', async () => {
    const cache = new ScanCache('/dev/null/not-a-dir/cache.json');
    const result = await scanManifests([NPM], options({ cache }));
    expect(result.errors.some((e) => e.startsWith('Could not save scan cache'))).toBe(true);
  });
});
