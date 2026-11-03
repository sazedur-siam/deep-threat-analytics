import { findNodeAtLocation, parseTree, type Node, type ParseError } from 'jsonc-parser';
import { readFile, realpath, stat } from 'node:fs/promises';
import * as path from 'node:path';
import { LineIndex } from '../core/text';
import type { DeclaredDep, Language, ResolvedDep, SourceRange } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { walkFiles } from './walk';

/**
 * DepThreat's own id. Its bundle contains every detection pattern, so scanning it would only
 * flag itself.
 */
export const SELF_EXTENSION_ID = 'mdsazedurrahman.deep-threat-analytics';

/** The manifest the editor keeps in its extensions folder. */
export const EXTENSIONS_MANIFEST = 'extensions.json';

const LANGUAGE_BY_EXT: Record<string, Language> = {
  '.js': 'javascript',
  '.cjs': 'javascript',
  '.mjs': 'javascript',
  '.ts': 'typescript',
  '.sh': 'shell',
  // There is no PowerShell rule language. `shell` runs the language-agnostic rules, which
  // include the PowerShell download-and-run patterns (iex/iwr, DownloadString, certutil).
  '.ps1': 'shell',
  '.psm1': 'shell',
};

/**
 * One entry of `<extensionsDir>/extensions.json`, as written by VS Code 1.7x+ and its forks:
 * `{ identifier: { id, uuid }, version, location: { fsPath, path, scheme }, relativeLocation }`.
 */
export interface InstalledExtension {
  /** Lower-case `publisher.name`. */
  id: string;
  version: string;
  relativeLocation?: string;
  /** Absolute folder from `location` (file scheme only). */
  location?: string;
  /** Range of the id string inside the manifest. */
  range: SourceRange;
}

const stringAt = (node: Node, at: Array<string | number>): string | undefined => {
  const value = findNodeAtLocation(node, at)?.value;
  return typeof value === 'string' && value ? value : undefined;
};

/** Parse an editor's extensions.json. Anything but a JSON array (a recommendations file) → []. */
export function parseExtensionsJson(text: string): InstalledExtension[] {
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { allowTrailingComma: true });
  if (!root || root.type !== 'array' || errors.length) return [];
  const lines = new LineIndex(text);
  const out: InstalledExtension[] = [];
  for (const entry of root.children ?? []) {
    if (entry.type !== 'object') continue;
    const idNode = findNodeAtLocation(entry, ['identifier', 'id']);
    if (typeof idNode?.value !== 'string' || !idNode.value.includes('.')) continue;
    const scheme = stringAt(entry, ['location', 'scheme']);
    const location =
      scheme === undefined || scheme === 'file'
        ? (stringAt(entry, ['location', 'fsPath']) ?? stringAt(entry, ['location', 'path']))
        : undefined;
    const relativeLocation = stringAt(entry, ['relativeLocation']);
    out.push({
      id: idNode.value.toLowerCase(),
      version: stringAt(entry, ['version']) ?? 'unknown',
      ...(relativeLocation ? { relativeLocation } : {}),
      ...(location ? { location } : {}),
      range: lines.range(idNode.offset + 1, idNode.offset + idNode.length - 1),
    });
  }
  return out;
}

/** True when `child` is strictly inside `parent` (lexically, after resolving `..`). */
function isInside(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/**
 * Folder of an installed extension, or undefined when it is missing or would point outside the
 * extensions folder (a tampered `relativeLocation: "../../somewhere"`).
 */
export async function extensionFolder(
  extensionsDir: string,
  ext: Pick<InstalledExtension, 'relativeLocation' | 'location'>,
): Promise<string | undefined> {
  const root = path.resolve(extensionsDir);
  const candidate = ext.relativeLocation
    ? path.resolve(root, ext.relativeLocation)
    : ext.location
      ? path.resolve(ext.location)
      : undefined;
  if (!candidate || !isInside(root, candidate)) return undefined;
  try {
    return (await stat(candidate)).isDirectory() ? candidate : undefined;
  } catch {
    return undefined;
  }
}

/** Is this the editor's extensions.json (and not a project's .vscode/extensions.json)? */
export function isExtensionsManifest(manifestPath: string): boolean {
  const parts = manifestPath.split(/[\\/]/);
  // A project's recommendations file lives in `.vscode/`; the editor's install manifest lives
  // in a folder named `extensions` (~/.vscode/extensions, ~/.cursor/extensions, ...).
  return parts.at(-1) === EXTENSIONS_MANIFEST && parts.at(-2) === 'extensions';
}

/**
 * Per-user data folders of VS Code and its forks (each keeps installed extensions in
 * `<folder>/extensions`), with the editor's display name.
 */
export const EDITOR_FOLDERS: ReadonlyArray<readonly [folder: string, editor: string]> = [
  ['.vscode', 'VS Code'],
  ['.vscode-insiders', 'VS Code Insiders'],
  ['.vscode-oss', 'VSCodium'],
  ['.cursor', 'Cursor'],
  ['.windsurf', 'Windsurf'],
  ['.vscode-server', 'VS Code Server'],
  ['.vscode-server-insiders', 'VS Code Insiders Server'],
  ['.cursor-server', 'Cursor Server'],
  ['.windsurf-server', 'Windsurf Server'],
];

/** Extensions folders to look in: the running editor's first, then the well-known ones. */
export function candidateExtensionDirs(home: string, currentDir?: string): string[] {
  return [
    ...(currentDir ? [currentDir] : []),
    ...EDITOR_FOLDERS.map(([folder]) => path.join(home, folder, 'extensions')),
  ];
}

/**
 * The extensions.json of every folder that has one, deduplicated by real path (a symlinked
 * ~/.cursor/extensions is scanned once), in the order given.
 */
export async function findExtensionManifests(dirs: readonly string[]): Promise<string[]> {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const dir of dirs) {
    const manifest = path.join(path.resolve(dir), EXTENSIONS_MANIFEST);
    if (!isExtensionsManifest(manifest)) continue;
    let real: string;
    try {
      real = await realpath(manifest);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    out.push(manifest);
  }
  return out;
}

/** `~/…` for paths in the home folder, so labels never spell out the user's home path. */
export function tildify(file: string, home: string): string {
  if (!home) return file;
  const rel = path.relative(home, file);
  if (rel === '') return '~';
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file;
  return `~/${rel.split(path.sep).join('/')}`;
}

/** Tree label for an extensions manifest: "Installed extensions — VS Code (~/.vscode/extensions)". */
export function extensionsManifestLabel(manifestPath: string, home: string): string {
  const dir = path.dirname(manifestPath);
  const folder = path.basename(path.dirname(dir));
  const editor = EDITOR_FOLDERS.find(([f]) => f === folder)?.[1];
  return `Installed extensions${editor ? ` — ${editor}` : ''} (${tildify(dir, home)})`;
}

function isTypeDeclaration(file: string): boolean {
  return /\.d\.[cm]?ts$/.test(file);
}

const isInNodeModules = (root: string, file: string) =>
  path.relative(root, file).split(path.sep).includes('node_modules');

export const vscodeExtensionsAdapter: EcosystemAdapter = {
  id: 'vscode',
  // OSV.dev has no ecosystem for editor extensions; lookups skip them.
  osvEcosystem: '',
  // Never part of a workspace scan: only the Scan Installed Extensions command passes these in.
  manifestGlobs: [],

  matches: isExtensionsManifest,

  parseManifest(manifestPath, text): DeclaredDep[] {
    return parseExtensionsJson(text).map((ext) => ({
      ecosystem: 'vscode',
      name: ext.id,
      versionSpec: ext.version,
      manifestPath,
      range: ext.range,
      isDev: false,
    }));
  },

  async resolve(manifestPath, declared, ctx) {
    const root = path.dirname(manifestPath);
    const entries = parseExtensionsJson(await readFile(manifestPath, 'utf8').catch(() => '[]'));
    const byKey = new Map(entries.map((e) => [`${e.id}@${e.version}`, e]));
    const out: ResolvedDep[] = [];
    const seen = new Set<string>();
    for (const dep of declared) {
      ctx.signal?.throwIfAborted();
      const key = `${dep.name}@${dep.versionSpec}`;
      if (dep.name === SELF_EXTENSION_ID || seen.has(key)) continue;
      seen.add(key);
      const entry = byKey.get(key);
      const dir = entry ? await extensionFolder(root, entry) : undefined;
      out.push({
        ecosystem: 'vscode',
        name: dep.name,
        version: dep.versionSpec,
        ...(dir ? { installPath: dir } : {}),
        // Extensions bundle their dependencies; there is no dependency graph to follow.
        direct: true,
        isDev: false,
        declared: dep,
      });
    }
    return out;
  },

  /**
   * The extension's own code first, then its bundled node_modules (where droppers like to hide)
   * with whatever is left of the per-package file budget, so a huge node_modules can never push
   * the extension's own entry point out of the scan.
   */
  async listSourceFiles(dep, limits) {
    const root = dep.installPath;
    if (!root) return [];
    const own = await walkFiles(root, {
      limits,
      skipDirs: new Set(['.git', 'node_modules']),
      include: (f) =>
        vscodeExtensionsAdapter.languageOf(f) !== undefined &&
        (path.basename(f) !== 'package.json' || path.dirname(f) === root),
    });
    const remaining = limits.maxFilesPerPackage - own.length;
    if (remaining <= 0) return own;
    const bundled = await walkFiles(root, {
      limits: { ...limits, maxFilesPerPackage: remaining },
      skipDirs: new Set(['.git']),
      include: (f) =>
        isInNodeModules(root, f) &&
        path.basename(f) !== 'package.json' &&
        vscodeExtensionsAdapter.languageOf(f) !== undefined,
    });
    return [...own, ...bundled];
  },

  languageOf(file) {
    if (path.basename(file) === 'package.json') return 'json';
    if (isTypeDeclaration(file)) return undefined;
    return LANGUAGE_BY_EXT[path.extname(file).toLowerCase()];
  },
};
