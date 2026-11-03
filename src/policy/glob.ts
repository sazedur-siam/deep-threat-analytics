import { normalizePythonName } from '../adapters/python/names';
import type { EcosystemId, PackageRef } from '../core/types';

const cache = new Map<string, RegExp>();

/**
 * Glob for names and ids: `*` matches any run of characters (including `/`, so `*crypto*`
 * matches `@scope/crypto-x`), `?` matches one character. Everything else is literal.
 */
export function globToRegExp(glob: string): RegExp {
  let re = cache.get(glob);
  if (!re) {
    const body = glob
      .split('')
      .map((ch) => (ch === '*' ? '.*' : ch === '?' ? '.' : ch.replace(/[\\^$.+()|{}[\]]/g, '\\$&')))
      .join('');
    re = new RegExp(`^${body}$`);
    cache.set(glob, re);
  }
  return re;
}

export function matchesGlob(value: string, glob: string): boolean {
  return globToRegExp(glob).test(value);
}

export function matchesAny(value: string, globs: readonly string[] | undefined): boolean {
  return (globs ?? []).some((g) => matchesGlob(value, g));
}

const ECOSYSTEMS: readonly EcosystemId[] = [
  'npm',
  'pypi',
  'go',
  'cargo',
  'maven',
  'composer',
  'vscode',
];

/**
 * Package pattern with an optional ecosystem prefix: `lodash`, `@types/*`, `pypi:requests`.
 * PyPI names compare in PEP 503 normalized form.
 */
export function matchesPackage(
  pkg: Pick<PackageRef, 'ecosystem' | 'name'>,
  pattern: string,
): boolean {
  let glob = pattern;
  const colon = pattern.indexOf(':');
  if (colon > 0) {
    const prefix = pattern.slice(0, colon) as EcosystemId;
    if (ECOSYSTEMS.includes(prefix)) {
      if (prefix !== pkg.ecosystem) return false;
      glob = pattern.slice(colon + 1);
    }
  }
  if (pkg.ecosystem === 'pypi') {
    return matchesGlob(normalizePythonName(pkg.name), normalizePythonName(glob));
  }
  return matchesGlob(pkg.name, glob);
}

/**
 * Version pattern: a glob (`4.*`) or an x-range (`4.x`, `4.17.x`). An empty pattern matches all.
 */
export function matchesVersion(version: string, pattern: string | undefined): boolean {
  if (!pattern) return true;
  return matchesGlob(version, pattern.replace(/(^|\.)[xX](?=\.|$)/g, '$1*'));
}
