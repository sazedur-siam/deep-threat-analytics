import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import * as path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { splitLines } from '../core/text';
import type { DeclaredDep, Language, ResolvedDep } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { parseIgnoreMarker } from './ignore';
import { walkFiles } from './walk';

const DEP_TABLE =
  /^(?:target\..+\.)?(dependencies|dev-dependencies|build-dependencies)$|^workspace\.dependencies$/;

function splitComment(line: string): { code: string; comment: string } {
  const m = /(^|\s)#/.exec(line);
  if (!m) return { code: line, comment: '' };
  const at = m.index + (m[1] as string).length;
  return { code: line.slice(0, at), comment: line.slice(at + 1) };
}

function tableKind(table: string): { isDev: boolean } | undefined {
  const m = DEP_TABLE.exec(table);
  if (!m) return undefined;
  // Build dependencies run on the developer's machine, so they are not "dev only".
  return { isDev: m[1] === 'dev-dependencies' };
}

interface Entry {
  key: string;
  crate: string;
  spec: string;
  local: boolean;
  isDev: boolean;
  line: number;
  col: number;
  comment: string;
}

const str = (value: string, key: string) =>
  new RegExp(`\\b${key}\\s*=\\s*["']([^"']*)["']`).exec(value)?.[1];

/** Parse Cargo.toml dependency tables, keeping the position of each dependency key. */
export function parseCargoToml(manifestPath: string, text: string): DeclaredDep[] {
  try {
    parseToml(text);
  } catch {
    return [];
  }
  const entries: Entry[] = [];
  let table = '';
  let current: Entry | undefined; // [dependencies.name] sub-table being filled
  splitLines(text).forEach((raw, line) => {
    const { code, comment } = splitComment(raw);
    const header = /^\s*\[\s*([^\]]+?)\s*\]\s*$/.exec(code);
    if (header) {
      table = (header[1] as string).replace(/\s*\.\s*/g, '.').replace(/["']/g, '');
      current = undefined;
      const sub = /^(.*)\.([^.]+)$/.exec(table);
      const kind = sub ? tableKind(sub[1] as string) : undefined;
      if (sub && kind) {
        const key = sub[2] as string;
        current = {
          key,
          crate: key,
          spec: '',
          local: false,
          isDev: kind.isDev,
          line,
          col: raw.indexOf(key),
          comment,
        };
        entries.push(current);
      }
      return;
    }
    const kv = /^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(code);
    if (!kv) return;
    const [, key, value] = kv as unknown as [string, string, string];
    if (current) {
      if (key === 'version') current.spec = str(`version=${value}`, 'version') ?? current.spec;
      if (key === 'package') current.crate = str(`package=${value}`, 'package') ?? current.crate;
      if (key === 'path') current.local = true;
      return;
    }
    const kind = tableKind(table);
    if (!kind) return;
    const quoted = /^\s*["']([^"']*)["']/.exec(value);
    entries.push({
      key,
      crate: str(value, 'package') ?? key,
      spec: quoted ? (quoted[1] as string) : (str(value, 'version') ?? ''),
      local: /\bpath\s*=/.test(value),
      isDev: kind.isDev,
      line,
      col: raw.indexOf(key),
      comment,
    });
  });
  return entries
    .filter((e) => !e.local)
    .map((e) => {
      const ignored = parseIgnoreMarker(e.comment);
      return {
        ecosystem: 'cargo',
        name: e.crate,
        versionSpec: e.spec,
        manifestPath,
        range: {
          startLine: e.line,
          startCol: e.col,
          endLine: e.line,
          endCol: e.col + e.key.length,
        },
        isDev: e.isDev,
        ...(ignored ? { ignoredRules: ignored } : {}),
      };
    });
}

export interface LockPackage {
  name: string;
  version: string;
  /** Missing for workspace members and path dependencies. */
  source?: string;
  dependencies: string[];
}

/** Nearest Cargo.lock at or above `startDir` (workspaces keep one lockfile at the root). */
export function findCargoLock(startDir: string): string | undefined {
  let dir = startDir;
  for (;;) {
    const lock = path.join(dir, 'Cargo.lock');
    if (existsSync(lock)) return lock;
    const parent = path.dirname(dir);
    if (parent === dir || existsSync(path.join(dir, '.git'))) return undefined;
    dir = parent;
  }
}

export async function readCargoLock(file: string): Promise<LockPackage[]> {
  try {
    const doc = parseToml(await readFile(file, 'utf8')) as { package?: unknown };
    const pkgs = Array.isArray(doc.package) ? (doc.package as Array<Record<string, unknown>>) : [];
    return pkgs
      .filter((p) => typeof p.name === 'string' && typeof p.version === 'string')
      .map((p) => ({
        name: p.name as string,
        version: p.version as string,
        ...(typeof p.source === 'string' ? { source: p.source } : {}),
        dependencies: Array.isArray(p.dependencies)
          ? p.dependencies.filter((d): d is string => typeof d === 'string')
          : [],
      }));
  } catch {
    return [];
  }
}

/** Lock dependency entries are "name", "name version" or "name version (source)". */
function lookup(lock: LockPackage[], entry: string): LockPackage | undefined {
  const [name, version] = entry.split(' ');
  const candidates = lock.filter((p) => p.name === name && (!version || p.version === version));
  return candidates.length === 1 ? candidates[0] : candidates.at(-1);
}

export function defaultCargoHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.CARGO_HOME ?? path.join(homedir(), '.cargo');
}

export interface RustAdapterOptions {
  cargoHome?: string;
}

export function createRustAdapter(options: RustAdapterOptions = {}): EcosystemAdapter {
  const adapter: EcosystemAdapter = {
    id: 'cargo',
    osvEcosystem: 'crates.io',
    manifestGlobs: ['**/Cargo.toml'],

    matches(manifestPath) {
      const parts = manifestPath.split(/[\\/]/);
      if (parts.at(-1) !== 'Cargo.toml') return false;
      if (parts.includes('vendor') || parts.includes('target')) return false;
      return !/[\\/]\.cargo[\\/](registry|git)[\\/]/.test(manifestPath);
    },

    parseManifest: parseCargoToml,

    async resolve(manifestPath, declared, ctx) {
      const lockFile = findCargoLock(path.dirname(manifestPath));
      const lock = lockFile ? await readCargoLock(lockFile) : [];
      const rootDir = lockFile ? path.dirname(lockFile) : path.dirname(manifestPath);
      const registrySrc = path.join(options.cargoHome ?? defaultCargoHome(), 'registry', 'src');
      let indexes: string[] = [];
      try {
        indexes = (await readdir(registrySrc)).sort().map((d) => path.join(registrySrc, d));
      } catch {
        // no registry cache yet
      }
      const locate = (pkg: { name: string; version: string }) => {
        const candidates = [
          path.join(rootDir, 'vendor', `${pkg.name}-${pkg.version}`),
          path.join(rootDir, 'vendor', pkg.name),
          ...indexes.map((i) => path.join(i, `${pkg.name}-${pkg.version}`)),
        ];
        return candidates.find((c) => existsSync(path.join(c, 'Cargo.toml')));
      };

      const out: ResolvedDep[] = [];
      const seen = new Set<string>();
      const wanted = declared.filter((d) => ctx.includeDev || !d.isDev);
      const ordered = [...wanted.filter((d) => !d.isDev), ...wanted.filter((d) => d.isDev)];
      for (const root of ordered) {
        ctx.signal?.throwIfAborted();
        const locked = lock
          .filter((p) => p.name === root.name && p.source)
          .sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }))
          .at(-1);
        const version =
          locked?.version ?? (/^\d[\w.+-]*$/.test(root.versionSpec) ? root.versionSpec : 'unknown');
        const key = `${root.name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const dir = locate({ name: root.name, version });
        out.push({
          ecosystem: 'cargo',
          name: root.name,
          version,
          ...(dir ? { installPath: dir } : {}),
          direct: true,
          isDev: root.isDev,
          declared: root,
        });
        if (!ctx.scanTransitive || !locked) continue;
        const queue = [{ pkg: locked, via: [root.name] }];
        while (queue.length) {
          ctx.signal?.throwIfAborted();
          const { pkg, via } = queue.shift()!;
          for (const entry of pkg.dependencies) {
            const child = lookup(lock, entry);
            if (!child?.source) continue; // workspace members and path crates are first-party
            const childKey = `${child.name}@${child.version}`;
            if (seen.has(childKey)) continue;
            seen.add(childKey);
            const childDir = locate(child);
            out.push({
              ecosystem: 'cargo',
              name: child.name,
              version: child.version,
              ...(childDir ? { installPath: childDir } : {}),
              direct: false,
              isDev: root.isDev,
              declared: root,
              via,
            });
            queue.push({ pkg: child, via: [...via, child.name] });
          }
        }
      }
      return out;
    },

    async listSourceFiles(dep, limits) {
      if (!dep.installPath) return [];
      return walkFiles(dep.installPath, {
        limits,
        // Tests, benches and examples are not compiled into dependents.
        skipDirs: new Set(['target', '.git', 'tests', 'benches', 'examples']),
        include: (f) => adapter.languageOf(f) !== undefined,
      });
    },

    languageOf(file): Language | undefined {
      if (file.endsWith('.rs')) return 'rust';
      return file.endsWith('.sh') ? 'shell' : undefined;
    },
  };
  return adapter;
}

export const rustAdapter = createRustAdapter();
