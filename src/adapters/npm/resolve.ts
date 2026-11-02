import { readFile, realpath, stat } from 'node:fs/promises';
import * as path from 'node:path';
import type { DeclaredDep, ResolvedDep } from '../../core/types';
import type { AdapterContext } from '../adapter';
import { findLockfile, readLockedVersions } from './lockfiles';

/** Safety cap on the number of installed packages walked per manifest. */
export const MAX_PACKAGES = 10_000;

interface InstalledPackage {
  dir: string;
  version: string;
  deps: string[];
}

async function isDirectory(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

function isInside(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** Read an installed package's version and runtime dependency names. */
async function readInstalled(dir: string): Promise<InstalledPackage | undefined> {
  try {
    const pkg = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')) as {
      version?: unknown;
      dependencies?: Record<string, unknown>;
      optionalDependencies?: Record<string, unknown>;
    };
    const deps = new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.optionalDependencies ?? {}),
    ]);
    return {
      dir,
      version: typeof pkg.version === 'string' ? pkg.version : 'unknown',
      deps: [...deps],
    };
  } catch {
    return undefined;
  }
}

/**
 * Node's module resolution: look for node_modules/<name> from `fromDir` upwards, without
 * leaving `rootDir`. Returns the real path (pnpm installs are symlinks into .pnpm).
 */
export async function locatePackage(
  name: string,
  fromDir: string,
  rootDir: string,
): Promise<string | undefined> {
  let dir = fromDir;
  for (;;) {
    const candidate = path.join(dir, 'node_modules', name);
    if (await isDirectory(candidate)) {
      const real = await realpath(candidate);
      if (await readInstalled(real)) return real;
    }
    if (dir === rootDir || !isInside(dir, rootDir)) return undefined;
    dir = path.dirname(dir);
  }
}

/** Workspace packages linked into node_modules are first-party code, not dependencies. */
function isThirdParty(realDir: string): boolean {
  return realDir.split(path.sep).includes('node_modules');
}

/**
 * Resolve declared deps against what is installed on disk, walking transitive runtime
 * dependencies breadth-first. Production roots are walked before dev roots, so a package
 * reachable from both is reported as production.
 */
export async function resolveNpm(
  manifestPath: string,
  declared: DeclaredDep[],
  ctx: AdapterContext,
): Promise<ResolvedDep[]> {
  const manifestDir = await realpath(path.dirname(manifestPath));
  const lock = findLockfile(manifestDir);
  const rootDir = lock ? await realpath(lock.dir) : manifestDir;
  const importer = lock ? path.relative(rootDir, manifestDir).split(path.sep).join('/') : '';
  const locked = lock ? await readLockedVersions(lock, importer, declared) : new Map();

  const results: ResolvedDep[] = [];
  const seen = new Set<string>();
  const wanted = declared.filter((d) => ctx.includeDev || !d.isDev);
  const ordered = [...wanted.filter((d) => !d.isDev), ...wanted.filter((d) => d.isDev)];

  for (const root of ordered) {
    ctx.signal?.throwIfAborted();
    const dir = await locatePackage(root.name, manifestDir, rootDir);
    const installed = dir ? await readInstalled(dir) : undefined;
    if (!dir || !installed) {
      const key = `missing:${root.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push({
        ecosystem: 'npm',
        name: root.name,
        version: locked.get(root.name) ?? root.versionSpec,
        direct: true,
        isDev: root.isDev,
        declared: root,
      });
      continue;
    }
    if (!isThirdParty(dir) || seen.has(dir)) continue;
    seen.add(dir);
    results.push({
      ecosystem: 'npm',
      name: root.name,
      version: installed.version,
      installPath: dir,
      direct: true,
      isDev: root.isDev,
      declared: root,
    });
    if (!ctx.scanTransitive) continue;

    const queue: Array<{ pkg: InstalledPackage; via: string[] }> = [
      { pkg: installed, via: [root.name] },
    ];
    while (queue.length) {
      ctx.signal?.throwIfAborted();
      const { pkg, via } = queue.shift()!;
      for (const name of pkg.deps) {
        if (seen.size >= MAX_PACKAGES) return results;
        const childDir = await locatePackage(name, pkg.dir, rootDir);
        if (!childDir || seen.has(childDir) || !isThirdParty(childDir)) continue;
        const child = await readInstalled(childDir);
        if (!child) continue;
        seen.add(childDir);
        results.push({
          ecosystem: 'npm',
          name,
          version: child.version,
          installPath: childDir,
          direct: false,
          isDev: root.isDev,
          declared: root,
          via,
        });
        queue.push({ pkg: child, via: [...via, name] });
      }
    }
  }
  return results;
}
