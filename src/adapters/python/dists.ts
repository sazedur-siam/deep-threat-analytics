import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { splitLines } from '../../core/text';
import { normalizePythonName, parseRequirement } from './names';

/** An installed distribution found in a site-packages directory. */
export interface Dist {
  name: string;
  version: string;
  sitePackages: string;
  /** Absolute path of the *.dist-info or *.egg-info directory. */
  metaDir: string;
  /** Installed file paths relative to sitePackages (from RECORD / installed-files.txt). */
  files: string[];
  /** Normalized names of runtime requirements (extras excluded). */
  requires: string[];
  topLevel: string[];
}

export type ProcessRunner = (
  file: string,
  args: string[],
  opts: { timeoutMs: number; signal?: AbortSignal },
) => Promise<string>;

/** execFile without a shell, from a neutral directory. */
export const defaultRunner: ProcessRunner = (file, args, { timeoutMs, signal }) =>
  new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, signal, cwd: tmpdir(), windowsHide: true, maxBuffer: 1024 * 1024 },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
  });

/**
 * -I (isolated mode) keeps the current directory and PYTHON* env vars off sys.path, so a
 * planted json.py or site customization in the project cannot run during discovery.
 */
export const SITE_PACKAGES_SCRIPT =
  'import json,site,sys;print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))';

const VENV_NAMES = ['.venv', 'venv', 'env'];

async function isDir(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

/** site-packages directories of a virtual environment root (POSIX and Windows layouts). */
async function venvSitePackages(venv: string): Promise<string[]> {
  const out: string[] = [];
  const winSite = path.join(venv, 'Lib', 'site-packages');
  if (await isDir(winSite)) out.push(winSite);
  try {
    for (const entry of (await readdir(path.join(venv, 'lib'))).sort()) {
      const site = path.join(venv, 'lib', entry, 'site-packages');
      if (/^python\d/.test(entry) && (await isDir(site))) out.push(site);
    }
  } catch {
    // no lib/ directory
  }
  return out;
}

/** Nearest virtual environment at or above `startDir`, stopping at a repository root. */
export function findVenv(startDir: string): string | undefined {
  let dir = startDir;
  for (;;) {
    for (const name of VENV_NAMES) {
      const venv = path.join(dir, name);
      if (existsSync(path.join(venv, 'pyvenv.cfg'))) return venv;
    }
    const parent = path.dirname(dir);
    if (parent === dir || existsSync(path.join(dir, '.git'))) return undefined;
    dir = parent;
  }
}

export interface DiscoveryOptions {
  trusted: boolean;
  interpreter?: string;
  runner: ProcessRunner;
  signal?: AbortSignal;
}

/**
 * Locate site-packages for a project. A virtual environment on disk is used without running
 * anything. Only in trusted workspaces is an interpreter executed to ask Python directly.
 */
export async function findSitePackages(
  manifestDir: string,
  opts: DiscoveryOptions,
): Promise<string[]> {
  const venv = findVenv(manifestDir);
  if (venv && !opts.interpreter) return venvSitePackages(venv);
  if (!opts.trusted) return venv ? venvSitePackages(venv) : [];
  const python = opts.interpreter || 'python3';
  try {
    const out = await opts.runner(python, ['-I', '-c', SITE_PACKAGES_SCRIPT], {
      timeoutMs: 10_000,
      signal: opts.signal,
    });
    const dirs = JSON.parse(out.trim()) as unknown;
    if (!Array.isArray(dirs)) return [];
    const existing: string[] = [];
    for (const d of dirs) if (typeof d === 'string' && (await isDir(d))) existing.push(d);
    return existing;
  } catch {
    return venv ? venvSitePackages(venv) : [];
  }
}

/** RECORD rows are CSV: path,hash,size, where the path may be quoted. */
export function parseRecord(text: string): string[] {
  const out: string[] = [];
  for (const line of splitLines(text)) {
    if (!line) continue;
    if (line.startsWith('"')) {
      const end = line.indexOf('"', 1);
      if (end > 0) out.push(line.slice(1, end));
    } else {
      out.push(line.split(',')[0] as string);
    }
  }
  return out;
}

/** Name, version and unconditional Requires-Dist entries from METADATA / PKG-INFO. */
export function parseMetadata(text: string): {
  name?: string;
  version?: string;
  requires: string[];
} {
  let name: string | undefined;
  let version: string | undefined;
  const requires: string[] = [];
  for (const line of splitLines(text)) {
    if (line === '') break; // headers end at the first blank line; the body is the description
    const m = /^([A-Za-z-]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, key, value] = m as unknown as [string, string, string];
    if (key === 'Name') name = value.trim();
    else if (key === 'Version') version = value.trim();
    else if (key === 'Requires-Dist') {
      const req = parseRequirement(value);
      if (req && !/\bextra\s*==/.test(req.marker ?? ''))
        requires.push(normalizePythonName(req.name));
    }
  }
  return { name, version, requires };
}

async function readOptional(file: string): Promise<string | undefined> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}

async function readDist(sitePackages: string, entry: string): Promise<Dist | undefined> {
  const metaDir = path.join(sitePackages, entry);
  const isDistInfo = entry.endsWith('.dist-info');
  const meta = await readOptional(path.join(metaDir, isDistInfo ? 'METADATA' : 'PKG-INFO'));
  const fromDirName = /^(.+?)-([^-]+?)\.(dist|egg)-info$/.exec(entry);
  const parsed = meta ? parseMetadata(meta) : { requires: [] as string[] };
  const rawName = parsed.name ?? fromDirName?.[1];
  if (!rawName) return undefined;
  const files = isDistInfo
    ? parseRecord((await readOptional(path.join(metaDir, 'RECORD'))) ?? '')
    : splitLines((await readOptional(path.join(metaDir, 'installed-files.txt'))) ?? '')
        .filter(Boolean)
        .map((f) => path.relative(sitePackages, path.resolve(metaDir, f)));
  const topLevel = splitLines((await readOptional(path.join(metaDir, 'top_level.txt'))) ?? '')
    .map((l) => l.trim())
    .filter(Boolean);
  return {
    name: normalizePythonName(rawName),
    version: parsed.version ?? fromDirName?.[2] ?? 'unknown',
    sitePackages,
    metaDir,
    files,
    requires: parsed.requires,
    topLevel,
  };
}

/** All distributions installed in the given site-packages dirs; earlier dirs win on conflicts. */
export async function indexDists(sitePackagesDirs: string[]): Promise<Map<string, Dist>> {
  const out = new Map<string, Dist>();
  for (const sp of sitePackagesDirs) {
    let entries: string[];
    try {
      entries = (await readdir(sp)).sort();
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.endsWith('.dist-info') && !entry.endsWith('.egg-info')) continue;
      const dist = await readDist(sp, entry);
      if (dist && !out.has(dist.name)) out.set(dist.name, dist);
    }
  }
  return out;
}
