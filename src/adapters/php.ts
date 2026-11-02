import { findNodeAtLocation, getNodeValue, parseTree, type ParseError } from 'jsonc-parser';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { LineIndex } from '../core/text';
import type { DeclaredDep, Language, ResolvedDep } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { walkFiles } from './walk';

/** Platform requirements are not packages: php, ext-json, lib-icu, composer-plugin-api, ... */
export function isPlatformPackage(name: string): boolean {
  // Real packages are always vendor/name; platform requirements never contain a slash.
  return !name.includes('/');
}

/** Packagist versions are often tagged `v1.2.3`; OSV and comparisons use `1.2.3`. */
export function normalizeComposerVersion(version: string): string {
  return /^v\d/.test(version) ? version.slice(1) : version;
}

/** Parse composer.json `require` / `require-dev`, with ranges on the package names. */
export function parseComposerJson(manifestPath: string, text: string): DeclaredDep[] {
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { allowTrailingComma: true });
  if (!root || root.type !== 'object' || errors.length) return [];
  const lines = new LineIndex(text);
  const ignoreNode = findNodeAtLocation(root, ['extra', 'depthreat', 'ignore']);
  const ignores =
    ignoreNode?.type === 'object' ? (getNodeValue(ignoreNode) as Record<string, unknown>) : {};
  const deps: DeclaredDep[] = [];
  for (const [section, isDev] of [
    ['require', false],
    ['require-dev', true],
  ] as const) {
    const node = findNodeAtLocation(root, [section]);
    if (node?.type !== 'object') continue;
    for (const prop of node.children ?? []) {
      const [nameNode, valueNode] = prop.children ?? [];
      if (typeof nameNode?.value !== 'string' || isPlatformPackage(nameNode.value)) continue;
      const name = nameNode.value.toLowerCase();
      const ignored = ignores[nameNode.value];
      deps.push({
        ecosystem: 'composer',
        name,
        versionSpec: typeof valueNode?.value === 'string' ? valueNode.value : '',
        manifestPath,
        range: lines.range(nameNode.offset + 1, nameNode.offset + nameNode.length - 1),
        isDev,
        ...(ignored === 'all'
          ? { ignoredRules: 'all' as const }
          : Array.isArray(ignored)
            ? { ignoredRules: ignored.filter((r): r is string => typeof r === 'string') }
            : {}),
      });
    }
  }
  return deps;
}

interface LockedPackage {
  name: string;
  version: string;
  require: string[];
  dev: boolean;
}

export async function readComposerLock(file: string): Promise<Map<string, LockedPackage>> {
  const out = new Map<string, LockedPackage>();
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
  } catch {
    return out;
  }
  for (const [key, dev] of [
    ['packages', false],
    ['packages-dev', true],
  ] as const) {
    const list = Array.isArray(doc[key]) ? (doc[key] as Array<Record<string, unknown>>) : [];
    for (const p of list) {
      if (typeof p.name !== 'string' || typeof p.version !== 'string') continue;
      const require = Object.keys((p.require as Record<string, unknown>) ?? {})
        .filter((n) => !isPlatformPackage(n))
        .map((n) => n.toLowerCase());
      out.set(p.name.toLowerCase(), {
        name: p.name.toLowerCase(),
        version: normalizeComposerVersion(p.version),
        require,
        dev,
      });
    }
  }
  return out;
}

function vendorDir(root: string, manifestText: string): string {
  try {
    const dir = (JSON.parse(manifestText) as { config?: { 'vendor-dir'?: unknown } }).config?.[
      'vendor-dir'
    ];
    return path.resolve(root, typeof dir === 'string' ? dir : 'vendor');
  } catch {
    return path.join(root, 'vendor');
  }
}

export const phpAdapter: EcosystemAdapter = {
  id: 'composer',
  osvEcosystem: 'Packagist',
  manifestGlobs: ['**/composer.json'],

  matches(manifestPath) {
    const parts = manifestPath.split(/[\\/]/);
    return parts.at(-1) === 'composer.json' && !parts.includes('vendor');
  },

  parseManifest: parseComposerJson,

  async resolve(manifestPath, declared, ctx) {
    const root = path.dirname(manifestPath);
    const vendor = vendorDir(root, await readFile(manifestPath, 'utf8').catch(() => '{}'));
    const lock = await readComposerLock(path.join(root, 'composer.lock'));
    const out: ResolvedDep[] = [];
    const seen = new Set<string>();
    const locate = (name: string) => {
      const dir = path.join(vendor, name);
      return existsSync(path.join(dir, 'composer.json')) ? dir : undefined;
    };
    const wanted = declared.filter((d) => ctx.includeDev || !d.isDev);
    const ordered = [...wanted.filter((d) => !d.isDev), ...wanted.filter((d) => d.isDev)];
    for (const rootDep of ordered) {
      ctx.signal?.throwIfAborted();
      if (seen.has(rootDep.name)) continue;
      seen.add(rootDep.name);
      const locked = lock.get(rootDep.name);
      const dir = locate(rootDep.name);
      out.push({
        ecosystem: 'composer',
        name: rootDep.name,
        version:
          locked?.version ??
          (/^v?\d[\w.-]*$/.test(rootDep.versionSpec)
            ? normalizeComposerVersion(rootDep.versionSpec)
            : 'unknown'),
        ...(dir ? { installPath: dir } : {}),
        direct: true,
        isDev: rootDep.isDev,
        declared: rootDep,
      });
      if (!ctx.scanTransitive || !locked) continue;
      const queue = [{ pkg: locked, via: [rootDep.name] }];
      while (queue.length) {
        ctx.signal?.throwIfAborted();
        const { pkg, via } = queue.shift()!;
        for (const name of pkg.require) {
          const child = lock.get(name);
          if (!child || seen.has(name)) continue;
          seen.add(name);
          const childDir = locate(name);
          out.push({
            ecosystem: 'composer',
            name,
            version: child.version,
            ...(childDir ? { installPath: childDir } : {}),
            direct: false,
            isDev: rootDep.isDev,
            declared: rootDep,
            via,
          });
          queue.push({ pkg: child, via: [...via, name] });
        }
      }
    }
    return out;
  },

  async listSourceFiles(dep, limits) {
    if (!dep.installPath) return [];
    return walkFiles(dep.installPath, {
      limits,
      skipDirs: new Set(['vendor', '.git', 'tests', 'Tests', 'test']),
      include: (f) => phpAdapter.languageOf(f) !== undefined,
    });
  },

  languageOf(file): Language | undefined {
    if (path.basename(file) === 'composer.json') return 'json';
    const ext = path.extname(file).toLowerCase();
    if (ext === '.php' || ext === '.phtml' || ext === '.inc') return 'php';
    return ext === '.sh' ? 'shell' : undefined;
  },
};
