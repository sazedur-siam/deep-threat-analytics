import * as path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { npmAdapter } from '../../../src/adapters/npm';
import { pythonAdapter } from '../../../src/adapters/python';
import { DEFAULT_SETTINGS, type DepThreatSettings } from '../../../src/config/settings';
import type { ResolvedDep } from '../../../src/core/types';
import { createPackageChecks } from '../../../src/scanners/packageChecks';

const DATA = path.resolve(__dirname, '../../../data');
const adapters = [npmAdapter, pythonAdapter];
const dep = (name: string, ecosystem: 'npm' | 'pypi' = 'npm'): ResolvedDep => ({
  ecosystem,
  name,
  version: '1.0.0',
  direct: true,
  isDev: false,
});
const settings = (online: DepThreatSettings['online']): DepThreatSettings => ({
  ...DEFAULT_SETTINGS,
  online,
});

describe('createPackageChecks', () => {
  it('only runs the offline typosquat check by default, without any network access', async () => {
    const fetchImpl = vi.fn();
    const checks = createPackageChecks(DEFAULT_SETTINGS, adapters, DATA, fetchImpl);
    expect(checks).toHaveLength(1);
    const { findings } = await checks[0]!([dep('lodahs'), dep('lodash'), dep('reqeusts', 'pypi')]);
    expect(findings.map((f) => f.package.name)).toEqual(['lodahs', 'reqeusts']);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('adds OSV and registry checks when enabled and maps OSV ecosystem names', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request, _init?: RequestInit) =>
      String(url).endsWith('/querybatch')
        ? Response.json({ results: [{}] })
        : new Response('', { status: 404 }),
    );
    const checks = createPackageChecks(
      settings({ osv: true, registryMetadata: true }),
      adapters,
      DATA,
      fetchImpl,
    );
    expect(checks).toHaveLength(3);
    await checks[1]!([dep('flask', 'pypi')]);
    const body = JSON.parse(String(fetchImpl.mock.calls[0]![1]?.body));
    expect(body.queries[0].package.ecosystem).toBe('PyPI');
    const registry = await checks[2]!([dep('flask', 'pypi')]);
    expect(registry.findings[0]?.ruleId).toBe('reputation/not-in-registry');
  });
});
