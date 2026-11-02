import { readFile, stat } from 'node:fs/promises';
import * as path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Language, ResolvedDep } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { defaultRunner, findSitePackages, indexDists, type ProcessRunner } from './python/dists';
import { parsePyproject, parseRequirementsTxt } from './python/manifests';
import { normalizePythonName, pinnedVersion } from './python/names';
import { walkFiles } from './walk';

const IGNORED_DIRS = ['site-packages', '.venv', 'venv', 'node_modules', '.tox'];
const SOURCE_EXT = new Set(['.py', '.pth', '.sh']);

/** Versions pinned by poetry.lock or uv.lock next to the manifest (normalized name → version). */
export async function readPythonLock(manifestDir: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const name of ['poetry.lock', 'uv.lock']) {
    let doc: Record<string, unknown>;
    try {
      doc = parseToml(await readFile(path.join(manifestDir, name), 'utf8'));
    } catch {
      continue;
    }
    const packages = Array.isArray(doc.package) ? doc.package : [];
    for (const pkg of packages as Array<Record<string, unknown>>) {
      if (typeof pkg.name === 'string' && typeof pkg.version === 'string') {
        out.set(normalizePythonName(pkg.name), pkg.version);
      }
    }
    if (out.size) return out;
  }
  return out;
}

export interface PythonAdapterOptions {
  /** Injectable for tests; the default runs execFile without a shell. */
  runProcess?: ProcessRunner;
}

export function createPythonAdapter(options: PythonAdapterOptions = {}): EcosystemAdapter {
  const runner = options.runProcess ?? defaultRunner;

  const adapter: EcosystemAdapter = {
    id: 'pypi',
    osvEcosystem: 'PyPI',
    manifestGlobs: ['**/requirements*.txt', '**/pyproject.toml'],

    matches(manifestPath) {
      const parts = manifestPath.split(/[\\/]/);
      const base = parts.at(-1) ?? '';
      if (parts.some((p) => IGNORED_DIRS.includes(p))) return false;
      return base === 'pyproject.toml' || /^requirements.*\.txt$/.test(base);
    },

    parseManifest(manifestPath, text) {
      return path.basename(manifestPath) === 'pyproject.toml'
        ? parsePyproject(manifestPath, text)
        : parseRequirementsTxt(manifestPath, text);
    },

    async resolve(manifestPath, declared, ctx) {
      const manifestDir = path.dirname(manifestPath);
      const sites = await findSitePackages(manifestDir, {
        trusted: ctx.trusted,
        interpreter: ctx.pythonInterpreter,
        runner,
        signal: ctx.signal,
      });
      const dists = await indexDists(sites);
      const locked = await readPythonLock(manifestDir);
      const results: ResolvedDep[] = [];
      const seen = new Set<string>();
      const wanted = declared.filter((d) => ctx.includeDev || !d.isDev);
      const ordered = [...wanted.filter((d) => !d.isDev), ...wanted.filter((d) => d.isDev)];

      for (const root of ordered) {
        ctx.signal?.throwIfAborted();
        if (seen.has(root.name)) continue;
        seen.add(root.name);
        const dist = dists.get(root.name);
        results.push({
          ecosystem: 'pypi',
          name: root.name,
          // The installed version is what gets scanned, so report that when present.
          version:
            dist?.version ?? locked.get(root.name) ?? pinnedVersion(root.versionSpec) ?? 'unknown',
          ...(dist ? { installPath: dist.sitePackages } : {}),
          direct: true,
          isDev: root.isDev,
          declared: root,
        });
        if (!ctx.scanTransitive || !dist) continue;
        const queue = [{ requires: dist.requires, via: [root.name] }];
        while (queue.length) {
          ctx.signal?.throwIfAborted();
          const { requires, via } = queue.shift()!;
          for (const name of requires) {
            if (seen.has(name)) continue;
            const child = dists.get(name);
            if (!child) continue;
            seen.add(name);
            results.push({
              ecosystem: 'pypi',
              name,
              version: child.version,
              installPath: child.sitePackages,
              direct: false,
              isDev: root.isDev,
              declared: root,
              via,
            });
            queue.push({ requires: child.requires, via: [...via, name] });
          }
        }
      }
      return results;
    },

    async listSourceFiles(dep, limits) {
      if (!dep.installPath) return [];
      const dist = (await indexDists([dep.installPath])).get(dep.name);
      if (!dist) return [];
      const include = (file: string) => adapter.languageOf(file) !== undefined;
      if (!dist.files.length) {
        const out: string[] = [];
        for (const top of dist.topLevel) {
          const dir = path.join(dist.sitePackages, top);
          out.push(
            ...(await walkFiles(dir, { limits, skipDirs: new Set(['__pycache__']), include })),
          );
          for (const ext of ['.py', '.pth']) {
            const single = path.join(dist.sitePackages, top + ext);
            if (
              await stat(single).then(
                (s) => s.isFile(),
                () => false,
              )
            )
              out.push(single);
          }
        }
        return [...new Set(out)].sort().slice(0, limits.maxFilesPerPackage);
      }
      const out: string[] = [];
      for (const rel of [...dist.files].sort()) {
        if (out.length >= limits.maxFilesPerPackage) break;
        const abs = path.resolve(dist.sitePackages, rel);
        const inside = !path.relative(dist.sitePackages, abs).startsWith('..');
        if (!inside || rel.split(/[\\/]/).includes('__pycache__') || !include(abs)) continue;
        const size = await stat(abs).then(
          (s) => (s.isFile() ? s.size : -1),
          () => -1,
        );
        if (size >= 0 && size <= limits.maxFileSizeBytes) out.push(abs);
      }
      return out;
    },

    languageOf(file): Language | undefined {
      const ext = path.extname(file).toLowerCase();
      if (!SOURCE_EXT.has(ext)) return undefined;
      return ext === '.sh' ? 'shell' : 'python';
    },
  };
  return adapter;
}

export const pythonAdapter = createPythonAdapter();
