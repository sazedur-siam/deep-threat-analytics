import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import {
  candidateExtensionDirs,
  extensionFolder,
  extensionsManifestLabel,
  findExtensionManifests,
  isExtensionsManifest,
  parseExtensionsJson,
  tildify,
  vscodeExtensionsAdapter as adapter,
} from '../../../src/adapters/vscodeExtensions';
import { DEFAULT_LIMITS, type ResolvedDep } from '../../../src/core/types';
import { makeExtensionsDir } from '../../helpers/vscodeExtensions';

const FIXTURE = path.resolve(__dirname, '../../fixtures/vscode-extensions');
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };
let dir: string;
let manifest: string;

beforeAll(async () => {
  dir = await makeExtensionsDir(FIXTURE);
  manifest = path.join(dir, 'extensions.json');
});

async function resolveFixture(): Promise<Map<string, ResolvedDep>> {
  const declared = adapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  const deps = await adapter.resolve(manifest, declared, ctx);
  return new Map(deps.map((d) => [d.name, d]));
}

describe('matching', () => {
  it.each([
    ['/home/u/.vscode/extensions/extensions.json', true],
    ['/home/u/.cursor/extensions/extensions.json', true],
    ['C:\\Users\\u\\.vscode\\extensions\\extensions.json', true],
    // A project's recommendations file, never an install manifest.
    ['/work/app/.vscode/extensions.json', false],
    ['/work/app/extensions.json', false],
    ['/home/u/.vscode/extensions/package.json', false],
  ])('%s → %s', (file, expected) => {
    expect(adapter.matches(file)).toBe(expected);
    expect(isExtensionsManifest(file)).toBe(expected);
  });

  it('never takes part in workspace scans', () => {
    expect(adapter.manifestGlobs).toEqual([]);
    expect(adapter.osvEcosystem).toBe('');
  });
});

describe('extensions.json parsing', () => {
  it('reads one dependency per entry, lower-cased, with the id range', async () => {
    const text = await readFile(manifest, 'utf8');
    const deps = adapter.parseManifest(manifest, text);
    expect(deps.map((d) => [d.name, d.versionSpec, d.ecosystem, d.isDev])).toEqual([
      ['glassworm-sample.color-theme-glow', '1.0.3', 'vscode', false],
      ['devtools-sample.ssh-helper', '0.2.0', 'vscode', false],
      ['esbenp.prettier-vscod', '11.0.0', 'vscode', false],
      ['clean-sample.word-count', '1.0.0', 'vscode', false],
      ['escape-sample.traversal', '6.6.6', 'vscode', false],
      ['mdsazedurrahman.deep-threat-analytics', '1.0.1', 'vscode', false],
    ]);
    const lines = text.split('\n');
    const clean = deps[3]!;
    expect(lines[clean.range.startLine]!.slice(clean.range.startCol, clean.range.endCol)).toBe(
      'Clean-Sample.word-count',
    );
    expect(clean.manifestPath).toBe(manifest);
  });

  it('rejects malformed JSON, recommendation files and odd entries', () => {
    expect(adapter.parseManifest('/x', '[{"identifier": {')).toEqual([]);
    expect(adapter.parseManifest('/x', '{"recommendations": ["ms-python.python"]}')).toEqual([]);
    expect(
      parseExtensionsJson(
        '[1, {"identifier": {"id": 3}}, {"identifier": {"id": "nodot"}}, {"identifier": {"id": "a.b"}}]',
      ),
    ).toMatchObject([{ id: 'a.b', version: 'unknown' }]);
  });

  it('reads file locations and ignores remote ones', () => {
    const [local, remote] = parseExtensionsJson(
      JSON.stringify([
        { identifier: { id: 'a.b' }, version: '1.0.0', location: { scheme: 'file', path: '/x/a' } },
        {
          identifier: { id: 'c.d' },
          version: '1.0.0',
          location: { scheme: 'vscode-remote', path: '/y' },
        },
      ]),
    );
    expect(local).toMatchObject({ id: 'a.b', location: '/x/a' });
    expect(remote?.location).toBeUndefined();
  });
});

describe('resolve', () => {
  it('locates installed extension folders', async () => {
    const deps = await resolveFixture();
    expect(deps.get('devtools-sample.ssh-helper')).toMatchObject({
      ecosystem: 'vscode',
      version: '0.2.0',
      installPath: path.join(dir, 'devtools-sample.ssh-helper-0.2.0'),
      direct: true,
      isDev: false,
    });
    expect(deps.get('clean-sample.word-count')?.installPath).toBe(
      path.join(dir, 'clean-sample.word-count-1.0.0'),
    );
  });

  it('skips DepThreat itself', async () => {
    expect((await resolveFixture()).has('mdsazedurrahman.deep-threat-analytics')).toBe(false);
  });

  it('never follows a location outside the extensions folder', async () => {
    // Even when the target exists.
    await mkdir(path.join(dir, '..', '..', 'escape'), { recursive: true });
    const escape = (await resolveFixture()).get('escape-sample.traversal');
    expect(escape).toBeDefined();
    expect(escape?.installPath).toBeUndefined();
    expect(await extensionFolder(dir, { location: path.join(dir, '..') })).toBeUndefined();
    expect(await extensionFolder(dir, { relativeLocation: '.' })).toBeUndefined();
    expect(await extensionFolder(dir, {})).toBeUndefined();
  });

  it('falls back to the absolute location and requires a folder', async () => {
    const target = path.join(dir, 'clean-sample.word-count-1.0.0');
    expect(await extensionFolder(dir, { location: target })).toBe(target);
    expect(await extensionFolder(dir, { relativeLocation: 'missing-1.0.0' })).toBeUndefined();
    expect(await extensionFolder(dir, { relativeLocation: 'extensions.json' })).toBeUndefined();
  });

  it('keeps extensions whose folder is missing, without an install path', async () => {
    const root = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-ext-')), 'extensions');
    await mkdir(root);
    const file = path.join(root, 'extensions.json');
    await writeFile(
      file,
      JSON.stringify([
        { identifier: { id: 'a.gone' }, version: '1.0.0', relativeLocation: 'a.gone-1.0.0' },
        { identifier: { id: 'a.gone' }, version: '1.0.0', relativeLocation: 'a.gone-1.0.0' },
      ]),
    );
    const declared = adapter.parseManifest(file, await readFile(file, 'utf8'));
    const deps = await adapter.resolve(file, declared, ctx);
    expect(deps).toHaveLength(1);
    expect(deps[0]?.installPath).toBeUndefined();
  });

  it('honors cancellation', async () => {
    const declared = adapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
    const signal = AbortSignal.abort();
    await expect(adapter.resolve(manifest, declared, { ...ctx, signal })).rejects.toThrow();
  });
});

describe('source files', () => {
  const rel = (dep: ResolvedDep, files: string[]) =>
    files.map((f) => path.relative(dep.installPath!, f).split(path.sep).join('/'));

  it('lists the extension code, its root package.json and bundled node_modules', async () => {
    const dep = (await resolveFixture()).get('devtools-sample.ssh-helper')!;
    const files = await adapter.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(rel(dep, files)).toEqual([
      'lib/extension.js',
      'package.json',
      'node_modules/helper-lib/index.js',
    ]);
  });

  it('scans the extension itself before node_modules when the file cap is hit', async () => {
    const dep = (await resolveFixture()).get('devtools-sample.ssh-helper')!;
    const files = await adapter.listSourceFiles(dep, { ...DEFAULT_LIMITS, maxFilesPerPackage: 2 });
    expect(rel(dep, files)).toEqual(['lib/extension.js', 'package.json']);
  });

  it('returns nothing for extensions that are not installed', async () => {
    const dep = (await resolveFixture()).get('escape-sample.traversal')!;
    expect(await adapter.listSourceFiles(dep, DEFAULT_LIMITS)).toEqual([]);
  });

  it('maps file types to rule languages', () => {
    expect(adapter.languageOf('/e/package.json')).toBe('json');
    expect(adapter.languageOf('/e/out/a.js')).toBe('javascript');
    expect(adapter.languageOf('/e/out/a.mjs')).toBe('javascript');
    expect(adapter.languageOf('/e/src/a.ts')).toBe('typescript');
    expect(adapter.languageOf('/e/src/a.d.ts')).toBeUndefined();
    expect(adapter.languageOf('/e/bin/run.sh')).toBe('shell');
    expect(adapter.languageOf('/e/bin/run.PS1')).toBe('shell');
    expect(adapter.languageOf('/e/media/logo.png')).toBeUndefined();
  });
});

describe('discovery and labels', () => {
  it('looks in the running editor first, then the well-known folders', () => {
    const dirs = candidateExtensionDirs('/home/u', '/opt/ext');
    expect(dirs[0]).toBe('/opt/ext');
    expect(dirs).toContain(path.join('/home/u', '.vscode', 'extensions'));
    expect(dirs).toContain(path.join('/home/u', '.cursor', 'extensions'));
    expect(dirs).toContain(path.join('/home/u', '.vscode-server', 'extensions'));
    expect(candidateExtensionDirs('/home/u')).not.toContain('/opt/ext');
  });

  it('keeps folders with an extensions.json, once per real path', async () => {
    const link = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-link-')), 'extensions');
    await symlink(dir, link, 'dir');
    const empty = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-none-')), 'extensions');
    await mkdir(empty);
    expect(await findExtensionManifests([dir, link, empty, dir, FIXTURE])).toEqual([manifest]);
  });

  it('shortens the home folder to ~', () => {
    expect(tildify('/home/u/.vscode/extensions', '/home/u')).toBe('~/.vscode/extensions');
    expect(tildify('/home/u', '/home/u')).toBe('~');
    expect(tildify('/opt/ext', '/home/u')).toBe('/opt/ext');
    expect(tildify('/opt/ext', '')).toBe('/opt/ext');
  });

  it('labels manifests by editor', () => {
    const label = (p: string) =>
      extensionsManifestLabel(path.join(p, 'extensions.json'), '/home/u');
    expect(label('/home/u/.vscode/extensions')).toBe(
      'Installed extensions — VS Code (~/.vscode/extensions)',
    );
    expect(label('/home/u/.cursor/extensions')).toBe(
      'Installed extensions — Cursor (~/.cursor/extensions)',
    );
    expect(label('/opt/portable/data/extensions')).toBe(
      'Installed extensions (/opt/portable/data/extensions)',
    );
  });
});
