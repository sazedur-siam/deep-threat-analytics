import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { normalizePythonName } from '../adapters/python/names';
import { mapLimit } from '../core/concurrency';
import { makeFindingId } from '../core/findings';
import type { EcosystemId, Finding, PackageRef, Severity } from '../core/types';
import { errorMessage, fetchJson, type OnlineOptions } from './http';

const DAY = 24 * 60 * 60 * 1000;

/** Bundled list of popular package names for an ecosystem ([] when there is none). */
export async function loadTopPackages(ecosystem: EcosystemId, dataDir: string): Promise<string[]> {
  try {
    const names = JSON.parse(
      await readFile(path.join(dataDir, 'top-packages', `${ecosystem}.json`), 'utf8'),
    ) as unknown;
    return Array.isArray(names) ? names.filter((n): n is string => typeof n === 'string') : [];
  } catch {
    return [];
  }
}

/** Optimal-string-alignment distance (Levenshtein plus adjacent transpositions). */
export function damerauLevenshtein(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = v;
    }
  }
  return d[a.length]![b.length]!;
}

const SEPARATORS = /[-_.]/;
const stripSeparators = (s: string) => s.replace(/[-_.]/g, '');
const LANG_AFFIX = /^(js|node|py|python)[-_.]|[-_.](js|node|py|python)$/g;
const RUST_AFFIX = /^(rs|rust)[-_.]|[-_.](rs|rust)$/g;
const HOMOGLYPHS: Array<[RegExp, string]> = [
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/rn/g, 'm'],
  [/vv/g, 'w'],
];

/** How names in one ecosystem are compared. */
interface SquatPolicy {
  normalize: (name: string) => string;
  /** Language prefixes/suffixes that squatters add (express-js, rust-serde). */
  affix?: RegExp;
  /**
   * Split a name into parts that are compared one at a time (Go module paths, Composer
   * vendor/name, Maven group segments + artifact). Exactly one part may differ, so a fork under
   * an unrelated owner or an artifact in an unrelated group is never flagged.
   */
  parts?: (name: string) => string[];
  /** Compare only the leading parts, so packages nested under a module path count as that module. */
  prefixParts?: boolean;
  /**
   * Conservative matching for registries full of numbered and short-named siblings
   * (aws-sdk-s3/aws-sdk-sqs, maven-jar-plugin/maven-war-plugin, serde_json/serde_json5):
   * one edit at most, only for names of 5+ characters, never inside a token of 3 or fewer
   * characters, and never for a trailing version number.
   */
  strict?: boolean;
}

const lower = (n: string) => n.toLowerCase();

const POLICIES: Record<EcosystemId, SquatPolicy> = {
  npm: { normalize: lower, affix: LANG_AFFIX },
  pypi: { normalize: normalizePythonName, affix: LANG_AFFIX },
  // crates.io treats - and _ as the same character: serde_json and serde-json are one crate.
  cargo: { normalize: (n) => n.toLowerCase().replace(/_/g, '-'), affix: RUST_AFFIX, strict: true },
  go: {
    // Major-version suffixes (/v2, gopkg.in/yaml.v3) name the same module.
    normalize: (n) =>
      n
        .toLowerCase()
        .replace(/\/v\d+$/, '')
        .replace(/^(gopkg\.in\/.+)\.v\d+$/, '$1'),
    parts: (n) => n.split('/'),
    prefixParts: true,
    strict: true,
  },
  composer: { normalize: lower, parts: (n) => n.split('/'), strict: true },
  maven: {
    // Scala binary-version suffixes (spark-core_2.12, akka-actor_3) name the same library.
    normalize: (n) => n.toLowerCase().replace(/_(2\.\d+|3)$/, ''),
    parts: (n) => {
      const [group = '', artifact] = n.split(':');
      return artifact === undefined ? [n] : [...group.split('.'), artifact];
    },
    strict: true,
  },
};

/** A versioned or short-named sibling of the target, which is not a squat (see SquatPolicy.strict). */
function isSibling(name: string, target: string): boolean {
  if (name.startsWith(target) && /^\d+$/.test(name.slice(target.length))) return true;
  const a = name.split(SEPARATORS);
  const b = target.split(SEPARATORS);
  if (a.length !== b.length || a.length < 2) return false;
  const diff = b.flatMap((t, i) => (t === a[i] ? [] : [t]));
  return diff.length === 1 && diff[0]!.length <= 3;
}

/** Why `name` looks like an imitation of `target`, or undefined. */
function squatReason(name: string, target: string, policy: SquatPolicy): string | undefined {
  if (name === target || target.length < 4) return undefined;
  if (policy.affix && name.replace(policy.affix, '') === target) {
    return 'adds a language prefix or suffix';
  }
  // Sub-packages and plugins of a popular package are not squats: lodash.merge, react-dom.
  if (name.startsWith(`${target}-`) || name.startsWith(`${target}.`)) return undefined;
  if (policy.strict && (name.startsWith(`${target}_`) || isSibling(name, target))) return undefined;
  if (stripSeparators(name) === stripSeparators(target)) return 'only the separators differ';
  let glyphs = name;
  for (const [re, ch] of HOMOGLYPHS) glyphs = glyphs.replace(re, ch);
  if (glyphs !== name && glyphs === target) return 'swaps look-alike characters';
  if (Math.abs(name.length - target.length) > 2) return undefined;
  if (policy.strict && target.length < 5) return undefined;
  const limit = !policy.strict && name.length >= 10 ? 2 : 1;
  return damerauLevenshtein(name, target) <= limit ? 'is a one-character typo away' : undefined;
}

/** squatReason for names made of parts: exactly one part may differ, and it must look like a squat. */
function partsSquatReason(
  name: string[],
  target: string[],
  policy: SquatPolicy,
): string | undefined {
  const compared = policy.prefixParts ? name.slice(0, target.length) : name;
  if (compared.length !== target.length) return undefined;
  const diff = target.flatMap((t, i) => (t === compared[i] ? [] : [i]));
  // No difference: the same module, or a package nested under it.
  if (diff.length !== 1) return undefined;
  const i = diff[0]!;
  const reason = squatReason(compared[i]!, target[i]!, policy);
  return reason && `"${compared[i]}" instead of "${target[i]}" ${reason}`;
}

/**
 * Offline check: is this package name a likely typosquat of a popular package? Names that are
 * themselves popular, scoped names, and very short names are never flagged.
 */
export function checkTyposquat(pkg: PackageRef, topNames: readonly string[]): Finding | undefined {
  const policy = POLICIES[pkg.ecosystem] ?? POLICIES.npm;
  const name = policy.normalize(pkg.name);
  if (name.length < 4 || name.startsWith('@')) return undefined;
  // Normalized name -> name as listed, for messages (serde-json -> serde_json).
  const top = new Map<string, string>();
  for (const n of topNames) {
    const key = policy.normalize(n);
    if (!top.has(key)) top.set(key, n);
  }
  if (top.has(name)) return undefined;
  const nameParts = policy.parts?.(name);
  for (const [target, listed] of top) {
    const reason = nameParts
      ? partsSquatReason(nameParts, policy.parts!(target), policy)
      : squatReason(name, target, policy);
    if (!reason) continue;
    const ruleId = 'reputation/typosquat';
    return {
      id: makeFindingId(ruleId, pkg),
      ruleId,
      title: `Possible typosquat of ${listed}`,
      category: 'reputation',
      severity: 'medium',
      message: `${pkg.name} looks like an imitation of the popular package ${listed} (${reason}). Check that you meant to install it.`,
      source: 'reputation',
      package: pkg,
    };
  }
  return undefined;
}

interface Signal {
  signal: string;
  title: string;
  severity: Severity;
  message: string;
}

function toFinding(pkg: PackageRef, s: Signal): Finding {
  const ruleId = `reputation/${s.signal}`;
  return {
    id: makeFindingId(ruleId, pkg),
    ruleId,
    title: s.title,
    category: 'reputation',
    severity: s.severity,
    message: s.message,
    source: 'reputation',
    package: pkg,
  };
}

const notInRegistry = (pkg: PackageRef, registry: string): Signal => ({
  signal: 'not-in-registry',
  title: 'Not found in the public registry',
  severity: 'high',
  message: `${pkg.name} does not exist on ${registry}. If it is meant to be a private package, a public package with the same name could be installed instead (dependency confusion).`,
});

function ageSignals(
  pkg: PackageRef,
  created: string | undefined,
  published: string | undefined,
  now: Date,
): Signal[] {
  const out: Signal[] = [];
  if (created && now.getTime() - Date.parse(created) < 30 * DAY) {
    out.push({
      signal: 'new-package',
      title: 'Very new package',
      severity: 'medium',
      message: `${pkg.name} was first published on ${created.slice(0, 10)}, less than 30 days ago.`,
    });
  }
  if (published && now.getTime() - Date.parse(published) < 7 * DAY) {
    out.push({
      signal: 'fresh-version',
      title: 'Version published in the last 7 days',
      severity: 'low',
      message: `${pkg.name}@${pkg.version} was published on ${published.slice(0, 10)}. Compromised releases are usually caught within days.`,
    });
  }
  return out;
}

interface NpmDoc {
  time?: Record<string, string>;
  repository?: unknown;
  homepage?: string;
  versions?: Record<
    string,
    {
      deprecated?: string;
      repository?: unknown;
      homepage?: string;
      _npmUser?: { name?: string };
      maintainers?: Array<{ name?: string }>;
    }
  >;
}

async function npmSignals(pkg: PackageRef, opts: OnlineOptions, now: Date): Promise<Signal[]> {
  const url = `https://registry.npmjs.org/${pkg.name.replace('/', '%2F')}`;
  const res = await fetchJson<NpmDoc>(url, opts);
  if (res.status === 404) return [notInRegistry(pkg, 'registry.npmjs.org')];
  if (!res.body) throw new Error(`HTTP ${res.status}`);
  const doc = res.body;
  const version = doc.versions?.[pkg.version];
  const out = ageSignals(pkg, doc.time?.created, doc.time?.[pkg.version], now);
  if (version?.deprecated) {
    out.push({
      signal: 'deprecated',
      title: 'Deprecated version',
      severity: 'low',
      message: `${pkg.name}@${pkg.version} is deprecated: ${version.deprecated}`,
    });
  }
  if (!doc.repository && !doc.homepage && !version?.repository && !version?.homepage) {
    out.push({
      signal: 'no-repository',
      title: 'No source repository',
      severity: 'info',
      message: `${pkg.name} does not link to a source repository or homepage.`,
    });
  }
  // A release published by someone who did not maintain the previous release.
  const releases = Object.keys(doc.versions ?? {})
    .filter((v) => doc.time?.[v])
    .sort((a, b) => Date.parse(doc.time![a]!) - Date.parse(doc.time![b]!));
  const idx = releases.indexOf(pkg.version);
  const prev = idx > 0 ? doc.versions?.[releases[idx - 1]!] : undefined;
  const publisher = version?._npmUser?.name;
  if (prev && publisher) {
    const previousPeople = new Set(
      [prev._npmUser?.name, ...(prev.maintainers ?? []).map((m) => m.name)].filter(Boolean),
    );
    if (previousPeople.size && !previousPeople.has(publisher)) {
      out.push({
        signal: 'maintainer-change',
        title: 'Published by a new maintainer',
        severity: 'medium',
        message: `${pkg.name}@${pkg.version} was published by ${publisher}, who did not maintain the previous release.`,
      });
    }
  }
  return out;
}

interface PypiDoc {
  info?: { home_page?: string | null; project_urls?: Record<string, string> | null };
  releases?: Record<
    string,
    Array<{ upload_time_iso_8601?: string; yanked?: boolean; yanked_reason?: string | null }>
  >;
}

async function pypiSignals(pkg: PackageRef, opts: OnlineOptions, now: Date): Promise<Signal[]> {
  const res = await fetchJson<PypiDoc>(
    `https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`,
    opts,
  );
  if (res.status === 404) return [notInRegistry(pkg, 'pypi.org')];
  if (!res.body) throw new Error(`HTTP ${res.status}`);
  const doc = res.body;
  const uploads = Object.values(doc.releases ?? {})
    .flat()
    .map((f) => f.upload_time_iso_8601)
    .filter((t): t is string => !!t)
    .sort();
  const files = doc.releases?.[pkg.version] ?? [];
  const published = files
    .map((f) => f.upload_time_iso_8601)
    .filter((t): t is string => !!t)
    .sort()[0];
  const out = ageSignals(pkg, uploads[0], published, now);
  const yanked = files.find((f) => f.yanked);
  if (yanked) {
    out.push({
      signal: 'yanked',
      title: 'Yanked release',
      severity: 'medium',
      message: `${pkg.name}==${pkg.version} was yanked from PyPI${yanked.yanked_reason ? `: ${yanked.yanked_reason}` : '.'}`,
    });
  }
  if (!doc.info?.home_page && !Object.keys(doc.info?.project_urls ?? {}).length) {
    out.push({
      signal: 'no-repository',
      title: 'No source repository',
      severity: 'info',
      message: `${pkg.name} does not link to a source repository or homepage.`,
    });
  }
  return out;
}

/**
 * Opt-in registry checks (npm and PyPI): package age, fresh versions, deprecations, yanked
 * releases, missing packages and maintainer changes. Only package names are sent. Returns
 * immediately when disabled and never throws on network errors.
 */
export async function fetchRegistryReputation(
  deps: readonly PackageRef[],
  opts: OnlineOptions & { now?: Date },
): Promise<{ findings: Finding[]; errors: string[] }> {
  if (!opts.enabled) return { findings: [], errors: [] };
  const now = opts.now ?? new Date();
  const unique = new Map<string, PackageRef>();
  for (const d of deps) {
    if (d.ecosystem === 'npm' || d.ecosystem === 'pypi')
      unique.set(`${d.ecosystem}:${d.name}@${d.version}`, d);
  }
  const findings: Finding[] = [];
  const errors: string[] = [];
  await mapLimit([...unique.values()], 8, async (pkg) => {
    try {
      const signals =
        pkg.ecosystem === 'npm'
          ? await npmSignals(pkg, opts, now)
          : await pypiSignals(pkg, opts, now);
      findings.push(...signals.map((s) => toFinding(pkg, s)));
    } catch (e) {
      errors.push(`Registry lookup for ${pkg.name} failed: ${errorMessage(e)}`);
    }
  });
  return { findings, errors };
}
