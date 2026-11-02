import * as path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { PackageRef } from '../../../src/core/types';
import {
  checkTyposquat,
  damerauLevenshtein,
  fetchRegistryReputation,
  loadTopPackages,
} from '../../../src/scanners/reputation';

const DATA = path.resolve(__dirname, '../../../data');
let npmTop: string[];
let pypiTop: string[];

beforeAll(async () => {
  npmTop = await loadTopPackages('npm', DATA);
  pypiTop = await loadTopPackages('pypi', DATA);
});

const npm = (name: string, version = '1.0.0'): PackageRef => ({ ecosystem: 'npm', name, version });
const pypi = (name: string, version = '1.0.0'): PackageRef => ({
  ecosystem: 'pypi',
  name,
  version,
});

describe('top package lists', () => {
  it('load bundled lists and tolerate missing ones', async () => {
    expect(npmTop.length).toBeGreaterThan(250);
    expect(pypiTop).toContain('python-dateutil');
    expect(await loadTopPackages('cargo', DATA)).toEqual([]);
  });
});

describe('damerauLevenshtein', () => {
  it.each([
    ['lodash', 'lodash', 0],
    ['lodahs', 'lodash', 1],
    ['lodas', 'lodash', 1],
    ['kitten', 'sitting', 3],
    ['', 'abc', 3],
  ])('%s vs %s = %d', (a, b, d) => {
    expect(damerauLevenshtein(a, b)).toBe(d);
  });
});

describe('checkTyposquat', () => {
  it.each([
    ['lodahs', 'lodash', npm],
    ['crossenv', 'cross-env', npm],
    ['electorn', 'electron', npm],
    ['express-js', 'express', npm],
    ['reqeusts', 'requests', pypi],
    ['python-dateutils', 'python-dateutil', pypi],
    ['djang0', 'django', pypi],
    ['Python_Dateutils', 'python-dateutil', pypi],
  ] as const)('flags %s as a squat of %s', (name, target, make) => {
    const f = checkTyposquat(make(name), make === npm ? npmTop : pypiTop);
    expect(f).toMatchObject({
      ruleId: 'reputation/typosquat',
      severity: 'medium',
      category: 'reputation',
    });
    expect(f?.title).toBe(`Possible typosquat of ${target}`);
  });

  it('never flags popular packages themselves', () => {
    for (const name of npmTop) expect(checkTyposquat(npm(name), npmTop), name).toBeUndefined();
    for (const name of pypiTop) expect(checkTyposquat(pypi(name), pypiTop), name).toBeUndefined();
  });

  it.each([
    'react-dom-utils',
    'lodash.pick',
    'eslint-plugin-foo',
    '@scope/lodahs',
    'abc',
    'my-internal-lib',
  ])('does not flag %s', (name) => {
    expect(checkTyposquat(npm(name), npmTop)).toBeUndefined();
  });
});

function npmDoc(over: Record<string, unknown> = {}) {
  return {
    repository: { url: 'git+https://example.invalid/repo.git' },
    time: {
      created: '2015-01-01T00:00:00Z',
      '0.9.0': '2020-01-01T00:00:00Z',
      '1.0.0': '2021-01-01T00:00:00Z',
    },
    versions: {
      '0.9.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }, { name: 'bob' }] },
      '1.0.0': { _npmUser: { name: 'bob' } },
    },
    ...over,
  };
}

function registry(routes: Record<string, unknown | number>) {
  return vi.fn(async (url: string | URL | Request) => {
    const hit = routes[String(url)];
    if (hit === undefined) return new Response('', { status: 500 });
    if (typeof hit === 'number') return new Response('', { status: hit });
    return Response.json(hit);
  });
}

const NOW = new Date('2026-11-02T00:00:00Z');
const ids = (r: { findings: Array<{ ruleId: string; package: { name: string } }> }) =>
  r.findings.map((f) => `${f.package.name}:${f.ruleId}`).sort();

describe('fetchRegistryReputation', () => {
  it('reports nothing for an established npm package', async () => {
    const fetchImpl = registry({ 'https://registry.npmjs.org/ok': npmDoc() });
    expect(
      await fetchRegistryReputation([npm('ok')], { enabled: true, fetchImpl, now: NOW }),
    ).toEqual({
      findings: [],
      errors: [],
    });
  });

  it('flags new, fresh, deprecated, unlinked and newly maintained npm releases', async () => {
    const fetchImpl = registry({
      'https://registry.npmjs.org/@scope%2Fnew': {
        time: { created: '2026-10-25T00:00:00Z', '1.0.0': '2026-11-01T00:00:00Z' },
        versions: { '1.0.0': { deprecated: 'use something else' } },
      },
      'https://registry.npmjs.org/taken-over': npmDoc({
        versions: {
          '0.9.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }] },
          '1.0.0': { _npmUser: { name: 'mallory' } },
        },
      }),
      'https://registry.npmjs.org/private-name': 404,
    });
    const result = await fetchRegistryReputation(
      [npm('@scope/new'), npm('taken-over'), npm('private-name')],
      { enabled: true, fetchImpl, now: NOW },
    );
    expect(result.errors).toEqual([]);
    expect(ids(result)).toEqual([
      '@scope/new:reputation/deprecated',
      '@scope/new:reputation/fresh-version',
      '@scope/new:reputation/new-package',
      '@scope/new:reputation/no-repository',
      'private-name:reputation/not-in-registry',
      'taken-over:reputation/maintainer-change',
    ]);
    const missing = result.findings.find((f) => f.ruleId === 'reputation/not-in-registry');
    expect(missing).toMatchObject({ severity: 'high', source: 'reputation' });
    expect(missing?.message).toContain('dependency confusion');
  });

  it('checks PyPI releases', async () => {
    const fetchImpl = registry({
      'https://pypi.org/pypi/old/json': {
        info: { project_urls: { Source: 'https://example.invalid' } },
        releases: {
          '1.0.0': [
            { upload_time_iso_8601: '2019-01-01T00:00:00Z', yanked: true, yanked_reason: 'broken' },
          ],
        },
      },
      'https://pypi.org/pypi/fresh/json': {
        info: { home_page: null, project_urls: null },
        releases: { '1.0.0': [{ upload_time_iso_8601: '2026-11-01T00:00:00Z' }] },
      },
      'https://pypi.org/pypi/gone/json': 404,
    });
    const result = await fetchRegistryReputation([pypi('old'), pypi('fresh'), pypi('gone')], {
      enabled: true,
      fetchImpl,
      now: NOW,
    });
    expect(ids(result)).toEqual([
      'fresh:reputation/fresh-version',
      'fresh:reputation/new-package',
      'fresh:reputation/no-repository',
      'gone:reputation/not-in-registry',
      'old:reputation/yanked',
    ]);
    expect(result.findings.find((f) => f.ruleId === 'reputation/yanked')?.message).toContain(
      'broken',
    );
  });

  it('reports registry errors and skips unsupported ecosystems', async () => {
    const fetchImpl = registry({});
    const result = await fetchRegistryReputation(
      [npm('down'), { ecosystem: 'cargo', name: 'serde', version: '1.0.0' }],
      { enabled: true, fetchImpl },
    );
    expect(result).toEqual({ findings: [], errors: ['Registry lookup for down failed: HTTP 500'] });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const pyDown = await fetchRegistryReputation([pypi('down')], { enabled: true, fetchImpl });
    expect(pyDown.errors).toEqual(['Registry lookup for down failed: HTTP 500']);
  });
});
