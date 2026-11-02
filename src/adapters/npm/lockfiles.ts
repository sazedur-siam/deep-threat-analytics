import { parse as parseYarnClassic } from '@yarnpkg/lockfile';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { DeclaredDep } from '../../core/types';

export const LOCKFILES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
] as const;
export type LockfileName = (typeof LOCKFILES)[number];

export interface FoundLockfile {
  dir: string;
  name: LockfileName;
}

/** Nearest lockfile at or above `startDir`, stopping at a repository root (`.git`). */
export function findLockfile(startDir: string): FoundLockfile | undefined {
  let dir = startDir;
  for (;;) {
    for (const name of LOCKFILES) {
      if (existsSync(path.join(dir, name))) return { dir, name };
    }
    const parent = path.dirname(dir);
    if (parent === dir || existsSync(path.join(dir, '.git'))) return undefined;
    dir = parent;
  }
}

/** pnpm versions may carry peer suffixes: `1.0.0(react@18.0.0)` or legacy `1.0.0_react@18.0.0`. */
export function stripPeerSuffix(version: string): string {
  return version.replace(/\(.*$/, '').replace(/_.*$/, '');
}

type Json = Record<string, unknown>;

function asObject(value: unknown): Json | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Json)
    : undefined;
}

function fromPackageLock(text: string, importer: string, names: string[]): Map<string, string> {
  const out = new Map<string, string>();
  const doc = asObject(JSON.parse(text));
  const packages = asObject(doc?.packages);
  const legacy = asObject(doc?.dependencies);
  for (const name of names) {
    const keys = [
      importer ? `${importer}/node_modules/${name}` : undefined,
      `node_modules/${name}`,
    ].filter((k): k is string => k !== undefined);
    let version: unknown;
    for (const key of keys) {
      version = asObject(packages?.[key])?.version;
      if (typeof version === 'string') break;
    }
    if (typeof version !== 'string') version = asObject(legacy?.[name])?.version;
    if (typeof version === 'string') out.set(name, version);
  }
  return out;
}

function fromPnpmLock(text: string, importer: string): Map<string, string> {
  const out = new Map<string, string>();
  const doc = asObject(parseYaml(text));
  const importers = asObject(doc?.importers);
  // Single-project lockfiles before v6 keep dependencies at the top level.
  const project = asObject(importers?.[importer || '.']) ?? (importers ? undefined : doc);
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, entry] of Object.entries(asObject(project?.[section]) ?? {})) {
      const raw = typeof entry === 'string' ? entry : asObject(entry)?.version;
      if (typeof raw === 'string' && !raw.startsWith('link:')) {
        out.set(name, stripPeerSuffix(raw));
      }
    }
  }
  return out;
}

function fromYarnLock(text: string, declared: DeclaredDep[]): Map<string, string> {
  const out = new Map<string, string>();
  if (text.includes('__metadata:')) {
    // Yarn Berry: keys like "a@npm:^1.0.0, a@npm:^1.1.0".
    const doc = asObject(parseYaml(text)) ?? {};
    const byDescriptor = new Map<string, string>();
    for (const [key, entry] of Object.entries(doc)) {
      const version = asObject(entry)?.version;
      if (typeof version !== 'string') continue;
      for (const descriptor of key.split(',')) byDescriptor.set(descriptor.trim(), version);
    }
    for (const dep of declared) {
      const spec = /^[a-z]+:/.test(dep.versionSpec) ? dep.versionSpec : `npm:${dep.versionSpec}`;
      const version = byDescriptor.get(`${dep.name}@${spec}`);
      if (version) out.set(dep.name, version);
    }
    return out;
  }
  const parsed = parseYarnClassic(text);
  if (parsed.type !== 'success') return out;
  const entries = parsed.object as Record<string, { version?: string }>;
  for (const dep of declared) {
    const version = entries[`${dep.name}@${dep.versionSpec}`]?.version;
    if (version) out.set(dep.name, version);
  }
  return out;
}

/**
 * Versions the lockfile pins for the declared (direct) dependencies of one project.
 * `importer` is the project directory relative to the lockfile directory ('' for the root).
 * Unreadable or malformed lockfiles yield an empty map.
 */
export async function readLockedVersions(
  lock: FoundLockfile,
  importer: string,
  declared: DeclaredDep[],
): Promise<Map<string, string>> {
  let text: string;
  try {
    text = await readFile(path.join(lock.dir, lock.name), 'utf8');
  } catch {
    return new Map();
  }
  try {
    switch (lock.name) {
      case 'package-lock.json':
      case 'npm-shrinkwrap.json':
        return fromPackageLock(
          text,
          importer,
          declared.map((d) => d.name),
        );
      case 'pnpm-lock.yaml':
        return fromPnpmLock(text, importer);
      case 'yarn.lock':
        return fromYarnLock(text, declared);
    }
  } catch {
    return new Map();
  }
}
