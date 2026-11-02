import { mapLimit } from '../core/concurrency';
import { makeFindingId } from '../core/findings';
import type { EcosystemId, Finding, PackageRef, Severity } from '../core/types';
import { normalizePythonName } from '../adapters/python/names';
import { errorMessage, fetchJson, isConcreteVersion, type OnlineOptions } from './http';

export type { OnlineOptions } from './http';

export const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const MAX_PAGES = 10;

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
    database_specific?: { severity?: string };
  }>;
  references?: Array<{ url: string }>;
  database_specific?: { severity?: string };
}

interface BatchResponse {
  results?: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }>;
}

/** Compare two version strings numerically, part by part; pre-releases sort before releases. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const [main = '', pre] = v.replace(/^v/, '').split(/-(.*)/s, 2);
    return { parts: main.split(/[.+]/), pre };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length); i++) {
    const p = x.parts[i] ?? '0';
    const q = y.parts[i] ?? '0';
    const np = Number(p);
    const nq = Number(q);
    const diff = Number.isNaN(np) || Number.isNaN(nq) ? p.localeCompare(q) : np - nq;
    if (diff) return Math.sign(diff);
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === undefined) return 1;
  if (y.pre === undefined) return -1;
  return x.pre.localeCompare(y.pre, undefined, { numeric: true });
}

const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

function roundUp(x: number): number {
  const i = Math.round(x * 100_000);
  return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
}

/** CVSS v3.x base score from a vector string, or undefined if it is not a valid v3 vector. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((kv) => kv.split(':') as [string, string]),
  );
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[
    m.PR as 'N' | 'L' | 'H'
  ];
  const w = (k: string) => CVSS3_WEIGHTS[k]?.[m[k] as string];
  const [av, ac, ui, c, i, a] = ['AV', 'AC', 'UI', 'C', 'I', 'A'].map(w);
  if ([av, ac, ui, c, i, a, pr].some((v) => v === undefined) || (m.S !== 'U' && m.S !== 'C')) {
    return undefined;
  }
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  return roundUp(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return score > 0 ? 'low' : 'info';
}

const GHSA_SEVERITY: Record<string, Severity> = {
  LOW: 'low',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

export function vulnSeverity(v: OsvVuln): Severity {
  const label =
    v.database_specific?.severity ??
    v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  if (label && GHSA_SEVERITY[label.toUpperCase()]) return GHSA_SEVERITY[label.toUpperCase()]!;
  for (const s of v.severity ?? []) {
    const score = cvss3BaseScore(s.score);
    if (score !== undefined) return severityFromScore(score);
  }
  return 'medium';
}

function sameName(ecosystem: EcosystemId, a: string, b: string): boolean {
  return ecosystem === 'pypi' ? normalizePythonName(a) === normalizePythonName(b) : a === b;
}

/** Lowest `fixed` version above the current one, for this package. */
export function fixedVersionFor(v: OsvVuln, pkg: PackageRef): string | undefined {
  const fixes = (v.affected ?? [])
    .filter((a) => !a.package?.name || sameName(pkg.ecosystem, a.package.name, pkg.name))
    .flatMap((a) => a.ranges ?? [])
    .flatMap((r) => r.events ?? [])
    .map((e) => e.fixed)
    .filter((f): f is string => !!f && compareVersions(f, pkg.version) > 0)
    .sort(compareVersions);
  return fixes[0];
}

export function vulnToFinding(v: OsvVuln, pkg: PackageRef): Finding {
  const malicious = v.id.startsWith('MAL-');
  const ruleId = `vulnerability/${v.id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
  const fixedVersion = malicious ? undefined : fixedVersionFor(v, pkg);
  const cve = v.aliases?.find((a) => a.startsWith('CVE-'));
  const summary = v.summary ?? v.details?.split('\n')[0] ?? 'Known vulnerability';
  return {
    id: makeFindingId(ruleId, pkg),
    ruleId,
    title: malicious ? `Known malicious package: ${v.id}` : `${v.id}: ${summary}`,
    category: malicious ? 'reputation' : 'vulnerability',
    severity: malicious ? 'critical' : vulnSeverity(v),
    message:
      `${pkg.name}@${pkg.version} is affected by ${v.id}${cve && cve !== v.id ? ` (${cve})` : ''}: ${summary}` +
      (fixedVersion ? ` Fixed in ${fixedVersion}.` : ''),
    source: 'osv',
    package: pkg,
    references: [
      ...(v.references ?? []).slice(0, 5).map((r) => r.url),
      `https://osv.dev/vulnerability/${v.id}`,
    ],
    ...(fixedVersion ? { fixedVersion } : {}),
  };
}

/**
 * Look up known vulnerabilities on OSV.dev. Only ecosystem, name and version are sent.
 * Returns immediately (no network) when `opts.enabled` is false. Never throws on network errors.
 */
export async function queryOsv(
  deps: readonly PackageRef[],
  osvEcosystemOf: (e: EcosystemId) => string,
  opts: OnlineOptions,
): Promise<{ findings: Finding[]; errors: string[] }> {
  if (!opts.enabled) return { findings: [], errors: [] };
  const unique = new Map<string, PackageRef>();
  for (const d of deps) {
    if (isConcreteVersion(d.version)) unique.set(`${d.ecosystem}:${d.name}@${d.version}`, d);
  }
  const pkgs = [...unique.values()];
  const errors: string[] = [];
  const idsByPkg = new Map<PackageRef, Set<string>>();

  try {
    for (let start = 0; start < pkgs.length; start += BATCH_SIZE) {
      let batch = pkgs
        .slice(start, start + BATCH_SIZE)
        .map((pkg) => ({ pkg, token: undefined as string | undefined }));
      for (let page = 0; batch.length && page < MAX_PAGES; page++) {
        const res = await fetchJson<BatchResponse>(`${OSV_API}/querybatch`, opts, {
          method: 'POST',
          body: {
            queries: batch.map(({ pkg, token }) => ({
              package: { name: pkg.name, ecosystem: osvEcosystemOf(pkg.ecosystem) },
              version: pkg.version,
              ...(token ? { page_token: token } : {}),
            })),
          },
        });
        if (!res.body) {
          errors.push(`OSV lookup failed (HTTP ${res.status})`);
          return { findings: [], errors };
        }
        const next: typeof batch = [];
        res.body.results?.forEach((r, i) => {
          const { pkg } = batch[i]!;
          const ids = idsByPkg.get(pkg) ?? new Set<string>();
          for (const v of r.vulns ?? []) ids.add(v.id);
          idsByPkg.set(pkg, ids);
          if (r.next_page_token) next.push({ pkg, token: r.next_page_token });
        });
        batch = next;
      }
    }
  } catch (e) {
    return { findings: [], errors: [`OSV lookup failed: ${errorMessage(e)}`] };
  }

  const allIds = [...new Set([...idsByPkg.values()].flatMap((s) => [...s]))];
  const vulns = new Map<string, OsvVuln>();
  await mapLimit(allIds, 8, async (id) => {
    try {
      const res = await fetchJson<OsvVuln>(`${OSV_API}/vulns/${encodeURIComponent(id)}`, opts);
      if (res.body) vulns.set(id, res.body);
      else errors.push(`OSV details for ${id} failed (HTTP ${res.status})`);
    } catch (e) {
      errors.push(`OSV details for ${id} failed: ${errorMessage(e)}`);
    }
  });

  const findings: Finding[] = [];
  for (const [pkg, ids] of idsByPkg) {
    for (const id of ids) {
      findings.push(vulnToFinding(vulns.get(id) ?? { id }, pkg));
    }
  }
  return { findings, errors };
}
