import { describe, expect, it, vi } from 'vitest';
import type { EcosystemId, PackageRef } from '../../../src/core/types';
import { errorMessage, fetchJson, isConcreteVersion, USER_AGENT } from '../../../src/scanners/http';
import {
  compareVersions,
  cvss3BaseScore,
  fixedVersionFor,
  queryOsv,
  vulnSeverity,
  vulnToFinding,
  type OsvVuln,
} from '../../../src/scanners/osv';
import { fetchRegistryReputation } from '../../../src/scanners/reputation';

const osvEco = (e: EcosystemId) => (e === 'pypi' ? 'PyPI' : 'npm');
const lodash: PackageRef = { ecosystem: 'npm', name: 'lodash', version: '4.17.15' };
const evil: PackageRef = { ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' };
const flask: PackageRef = { ecosystem: 'pypi', name: 'flask', version: '0.12' };

const VULNS: Record<string, OsvVuln> = {
  'GHSA-aaaa-bbbb-cccc': {
    id: 'GHSA-aaaa-bbbb-cccc',
    summary: 'Prototype pollution in lodash',
    aliases: ['CVE-2020-8203'],
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }],
      },
      { package: { name: 'lodash-es' }, ranges: [{ events: [{ fixed: '4.17.16' }] }] },
    ],
    references: [{ url: 'https://example.invalid/advisory' }],
  },
  'PYSEC-2019-1': {
    id: 'PYSEC-2019-1',
    details: 'Denial of service\nmore text',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
    affected: [
      { package: { name: 'Flask' }, ranges: [{ events: [{ fixed: '1.0' }, { fixed: '0.12.3' }] }] },
    ],
  },
  'MAL-2024-1': { id: 'MAL-2024-1', summary: 'Malicious code in evil-pkg' },
};

function mockOsv(opts: { paginate?: boolean; failDetails?: boolean; status?: number } = {}) {
  let page = 0;
  return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    if (opts.status) return new Response('', { status: opts.status });
    if (u.endsWith('/querybatch')) {
      const body = JSON.parse(String(init?.body)) as {
        queries: Array<{ package: { name: string } }>;
      };
      const results = body.queries.map((q) => {
        if (q.package.name === 'lodash') {
          if (opts.paginate && page++ === 0) {
            return { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }], next_page_token: 't1' };
          }
          return {
            vulns: opts.paginate ? [{ id: 'GHSA-extra' }] : [{ id: 'GHSA-aaaa-bbbb-cccc' }],
          };
        }
        if (q.package.name === 'flask') return { vulns: [{ id: 'PYSEC-2019-1' }] };
        if (q.package.name === 'evil-pkg') return { vulns: [{ id: 'MAL-2024-1' }] };
        return {};
      });
      return Response.json({ results });
    }
    const id = decodeURIComponent(u.split('/').pop()!);
    if (opts.failDetails || !VULNS[id]) return new Response('', { status: 500 });
    return Response.json(VULNS[id]);
  });
}

describe('version helpers', () => {
  it.each([
    ['1.2.10', '1.2.9', 1],
    ['1.0', '1.0.0', 0],
    ['2.0.0-beta.2', '2.0.0-beta.10', -1],
    ['2.0.0-rc.1', '2.0.0', -1],
    ['2.0.0', '2.0.0-rc.1', 1],
    ['v1.0.0', '1.0.0', 0],
    ['1.0.a', '1.0.b', -1],
  ])('compareVersions(%s, %s) = %d', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
  });

  it('recognizes concrete versions', () => {
    expect(isConcreteVersion('4.17.15')).toBe(true);
    expect(isConcreteVersion('1.0.0-rc.1')).toBe(true);
    expect(isConcreteVersion('^1.0.0')).toBe(false);
    expect(isConcreteVersion('unknown')).toBe(false);
    expect(isConcreteVersion('>=2')).toBe(false);
  });
});

describe('CVSS v3', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1],
    ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
    ['CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N', 4.6],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s → %d', (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  it('rejects other formats', () => {
    expect(cvss3BaseScore('CVSS:4.0/AV:N')).toBeUndefined();
    expect(cvss3BaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeUndefined();
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H')).toBeUndefined();
  });
});

describe('vulnerability mapping', () => {
  it('maps severities from labels, CVSS vectors, or defaults', () => {
    expect(vulnSeverity(VULNS['GHSA-aaaa-bbbb-cccc']!)).toBe('high');
    expect(vulnSeverity(VULNS['PYSEC-2019-1']!)).toBe('high');
    expect(vulnSeverity({ id: 'x', database_specific: { severity: 'MODERATE' } })).toBe('medium');
    expect(vulnSeverity({ id: 'x', affected: [{ database_specific: { severity: 'LOW' } }] })).toBe(
      'low',
    );
    expect(
      vulnSeverity({
        id: 'x',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      }),
    ).toBe('critical');
    expect(
      vulnSeverity({
        id: 'x',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N' }],
      }),
    ).toBe('low');
    expect(vulnSeverity({ id: 'x' })).toBe('medium');
  });

  it('picks the lowest fixed version above the current one for this package', () => {
    expect(fixedVersionFor(VULNS['GHSA-aaaa-bbbb-cccc']!, lodash)).toBe('4.17.19');
    expect(fixedVersionFor(VULNS['PYSEC-2019-1']!, flask)).toBe('0.12.3');
    expect(
      fixedVersionFor(VULNS['GHSA-aaaa-bbbb-cccc']!, { ...lodash, version: '5.0.0' }),
    ).toBeUndefined();
  });

  it('builds findings for vulnerabilities and malicious packages', () => {
    const f = vulnToFinding(VULNS['GHSA-aaaa-bbbb-cccc']!, lodash);
    expect(f).toMatchObject({
      ruleId: 'vulnerability/ghsa-aaaa-bbbb-cccc',
      category: 'vulnerability',
      source: 'osv',
      severity: 'high',
      fixedVersion: '4.17.19',
      title: 'GHSA-aaaa-bbbb-cccc: Prototype pollution in lodash',
    });
    expect(f.message).toContain('(CVE-2020-8203)');
    expect(f.message).toContain('Fixed in 4.17.19.');
    expect(f.references?.at(-1)).toBe('https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc');
    const mal = vulnToFinding(VULNS['MAL-2024-1']!, evil);
    expect(mal).toMatchObject({ category: 'reputation', severity: 'critical' });
    expect(mal.title).toBe('Known malicious package: MAL-2024-1');
    expect(vulnToFinding({ id: 'X-1' }, lodash).title).toBe('X-1: Known vulnerability');
  });
});

describe('queryOsv', () => {
  it('makes no network calls when disabled', async () => {
    const fetchImpl = vi.fn();
    const osv = await queryOsv([lodash], osvEco, { enabled: false, fetchImpl });
    const registry = await fetchRegistryReputation([lodash, flask], { enabled: false, fetchImpl });
    expect(osv).toEqual({ findings: [], errors: [] });
    expect(registry).toEqual({ findings: [], errors: [] });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('sends only ecosystem, name and version', async () => {
    const fetchImpl = mockOsv();
    await queryOsv([lodash, flask], osvEco, { enabled: true, fetchImpl });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe('https://api.osv.dev/v1/querybatch');
    expect(JSON.parse(String(init?.body))).toEqual({
      queries: [
        { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' },
        { package: { name: 'flask', ecosystem: 'PyPI' }, version: '0.12' },
      ],
    });
    expect((init?.headers as Record<string, string>)['User-Agent']).toBe(USER_AGENT);
  });

  it('never sends editor extensions, which OSV does not cover', async () => {
    const extension: PackageRef = {
      ecosystem: 'vscode',
      name: 'ms-python.python',
      version: '1.0.0',
    };
    const none = vi.fn();
    expect(await queryOsv([extension], () => 'npm', { enabled: true, fetchImpl: none })).toEqual({
      findings: [],
      errors: [],
    });
    expect(none).not.toHaveBeenCalled();
    const fetchImpl = mockOsv();
    await queryOsv([extension, lodash], osvEco, { enabled: true, fetchImpl });
    const queries = JSON.parse(String(fetchImpl.mock.calls[0]![1]?.body)).queries;
    expect(queries).toEqual([
      { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' },
    ]);
  });

  it('skips ecosystems without an OSV name', async () => {
    const fetchImpl = vi.fn();
    expect(await queryOsv([lodash], () => '', { enabled: true, fetchImpl })).toEqual({
      findings: [],
      errors: [],
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('returns findings for every affected package and skips non-concrete versions', async () => {
    const fetchImpl = mockOsv();
    const { findings, errors } = await queryOsv(
      [lodash, lodash, flask, evil, { ...lodash, name: 'x', version: '^1.0.0' }],
      osvEco,
      { enabled: true, fetchImpl },
    );
    expect(errors).toEqual([]);
    expect(findings.map((f) => `${f.package.name}:${f.ruleId}`).sort()).toEqual([
      'evil-pkg:vulnerability/mal-2024-1',
      'flask:vulnerability/pysec-2019-1',
      'lodash:vulnerability/ghsa-aaaa-bbbb-cccc',
    ]);
    const queries = JSON.parse(String(fetchImpl.mock.calls[0]![1]?.body)).queries;
    expect(queries).toHaveLength(3);
  });

  it('follows pagination tokens', async () => {
    const fetchImpl = mockOsv({ paginate: true });
    const { findings, errors } = await queryOsv([lodash], osvEco, { enabled: true, fetchImpl });
    const batchCalls = fetchImpl.mock.calls.filter(([u]) => String(u).endsWith('/querybatch'));
    expect(batchCalls).toHaveLength(2);
    expect(JSON.parse(String(batchCalls[1]![1]?.body)).queries[0].page_token).toBe('t1');
    expect(findings).toHaveLength(2);
    expect(errors).toEqual(['OSV details for GHSA-extra failed (HTTP 500)']);
  });

  it('splits more than 1000 packages into several batches', async () => {
    const fetchImpl = mockOsv();
    const many = Array.from({ length: 1001 }, (_, i) => ({ ...lodash, name: `pkg-${i}` }));
    await queryOsv(many, osvEco, { enabled: true, fetchImpl });
    expect(fetchImpl.mock.calls.filter(([u]) => String(u).endsWith('/querybatch'))).toHaveLength(2);
  });

  it('reports HTTP and network errors instead of throwing', async () => {
    expect(
      await queryOsv([lodash], osvEco, { enabled: true, fetchImpl: mockOsv({ status: 503 }) }),
    ).toEqual({
      findings: [],
      errors: ['OSV lookup failed (HTTP 503)'],
    });
    const offline = vi.fn(async () => {
      throw new TypeError('fetch failed');
    });
    expect(
      (await queryOsv([lodash], osvEco, { enabled: true, fetchImpl: offline })).errors,
    ).toEqual(['OSV lookup failed: fetch failed']);
    const details = await queryOsv([lodash], osvEco, {
      enabled: true,
      fetchImpl: mockOsv({ failDetails: true }),
    });
    expect(details.findings[0]?.title).toBe('GHSA-aaaa-bbbb-cccc: Known vulnerability');
    expect(details.errors).toHaveLength(1);
  });

  it('reports detail fetch exceptions per vulnerability', async () => {
    const base = mockOsv();
    const flaky = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).includes('/vulns/')) throw new Error('reset');
      return base(url, init);
    });
    const { errors } = await queryOsv([lodash], osvEco, { enabled: true, fetchImpl: flaky });
    expect(errors).toEqual(['OSV details for GHSA-aaaa-bbbb-cccc failed: reset']);
  });

  it('honors timeouts and caller cancellation', async () => {
    const hang = vi.fn(
      (_u: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_r, reject) =>
          init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)),
        ),
    );
    const timedOut = await queryOsv([lodash], osvEco, {
      enabled: true,
      fetchImpl: hang,
      timeoutMs: 5,
    });
    expect(timedOut.errors).toEqual(['OSV lookup failed: request timed out']);
    const ctrl = new AbortController();
    const pending = queryOsv([lodash], osvEco, {
      enabled: true,
      fetchImpl: hang,
      signal: ctrl.signal,
    });
    ctrl.abort(new Error('cancelled'));
    expect((await pending).errors).toEqual(['OSV lookup failed: cancelled']);
  });
});

describe('http helpers', () => {
  it('formats errors', () => {
    expect(errorMessage('plain')).toBe('plain');
    expect(errorMessage(new Error('boom'))).toBe('boom');
  });

  it('returns status without a body for HTTP errors', async () => {
    const fetchImpl = vi.fn(async () => new Response('', { status: 404 }));
    expect(await fetchJson('https://x.invalid', { enabled: true, fetchImpl })).toEqual({
      status: 404,
    });
  });
});
