import { cp, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import { npmAdapter } from '../../../src/adapters/npm';
import { parsePackageJson } from '../../../src/adapters/npm/manifest';
import {
  findLockfile,
  readLockedVersions,
  stripPeerSuffix,
} from '../../../src/adapters/npm/lockfiles';
import { locatePackage } from '../../../src/adapters/npm/resolve';
import { DEFAULT_LIMITS, type ResolvedDep } from '../../../src/core/types';

const FIXTURES = path.resolve(__dirname, '../../fixtures');
const SAMPLE = path.join(FIXTURES, 'npm-sample');
const ctx: AdapterContext = { trusted: true, includeDev: false, scanTransitive: true };

async function resolveFixture(dir: string, overrides: Partial<AdapterContext> = {}) {
  const manifest = path.join(dir, 'package.json');
  const declared = npmAdapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return npmAdapter.resolve(manifest, declared, { ...ctx, ...overrides });
}

function byName(deps: ResolvedDep[]): Map<string, ResolvedDep> {
  return new Map(deps.map((d) => [d.name, d]));
}

describe('parsePackageJson', () => {
  const text = `{
  "dependencies": { "a": "^1.0.0", "@scope/b": "2.0.0" },
  "devDependencies": {
    "c": "*"
  },
  "depthreat": { "ignore": { "a": ["network/*", 3], "c": "all", "x": [] } }
}`;
  const deps = parsePackageJson('/p/package.json', text);

  it('collects runtime and dev dependencies with specs', () => {
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['a', '^1.0.0', false],
      ['@scope/b', '2.0.0', false],
      ['c', '*', true],
    ]);
    expect(deps[0]).toMatchObject({ ecosystem: 'npm', manifestPath: '/p/package.json' });
  });

  it('ranges cover the dependency name inside its quotes', () => {
    expect(deps[0]?.range).toEqual({ startLine: 1, startCol: 21, endLine: 1, endCol: 22 });
    expect(deps[2]?.range).toEqual({ startLine: 3, startCol: 5, endLine: 3, endCol: 6 });
    const line = text.split('\n')[1]!;
    const r = deps[1]!.range;
    expect(line.slice(r.startCol, r.endCol)).toBe('@scope/b');
  });

  it('reads inline ignores', () => {
    expect(deps[0]?.ignoredRules).toEqual(['network/*']);
    expect(deps[1]?.ignoredRules).toBeUndefined();
    expect(deps[2]?.ignoredRules).toBe('all');
  });

  it('returns nothing for malformed or non-object JSON', () => {
    expect(parsePackageJson('/p', '{ "dependencies": { "a": ')).toEqual([]);
    expect(parsePackageJson('/p', '[]')).toEqual([]);
    expect(parsePackageJson('/p', '{ "dependencies": [] }')).toEqual([]);
  });

  it('keeps a name listed in two sections', () => {
    const both = parsePackageJson(
      '/p',
      '{ "dependencies": { "a": "1" }, "peerDependencies": { "a": "1" } }',
    );
    expect(both).toHaveLength(2);
  });
});

describe('lockfiles', () => {
  it('strips pnpm peer suffixes', () => {
    expect(stripPeerSuffix('1.0.0(react@18.0.0)')).toBe('1.0.0');
    expect(stripPeerSuffix('1.0.0_react@18.0.0')).toBe('1.0.0');
    expect(stripPeerSuffix('1.0.0')).toBe('1.0.0');
  });

  it('finds the nearest lockfile', () => {
    expect(findLockfile(path.join(SAMPLE, 'node_modules'))).toEqual({
      dir: SAMPLE,
      name: 'package-lock.json',
    });
  });

  it('reads versions from each lockfile format', async () => {
    const decl = (dir: string) =>
      readFile(path.join(dir, 'package.json'), 'utf8').then((t) =>
        parsePackageJson(path.join(dir, 'package.json'), t),
      );
    const cases: Array<[string, string, string]> = [
      ['npm-sample', 'package-lock.json', 'not-installed=4.2.1'],
      ['npm-pnpm', 'pnpm-lock.yaml', 'pnpm-a=1.0.0'],
      ['npm-yarn-classic', 'yarn.lock', 'yarn-missing=0.5.4'],
      ['npm-yarn-berry', 'yarn.lock', 'yarn-missing=0.5.4'],
    ];
    for (const [fixture, name, expected] of cases) {
      const dir = path.join(FIXTURES, fixture);
      const versions = await readLockedVersions({ dir, name } as never, '', await decl(dir));
      const [pkg, version] = expected.split('=') as [string, string];
      expect(versions.get(pkg), fixture).toBe(version);
    }
  });

  it('tolerates missing and malformed lockfiles', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-lock-'));
    expect(await readLockedVersions({ dir, name: 'yarn.lock' }, '', [])).toEqual(new Map());
    const bad = path.join(FIXTURES, 'npm-sample');
    expect(await readLockedVersions({ dir: bad, name: 'pnpm-lock.yaml' as never }, '', [])).toEqual(
      new Map(),
    );
  });
});

describe('npm resolve', () => {
  it('resolves direct and transitive deps from the installed tree', async () => {
    const deps = byName(await resolveFixture(SAMPLE));
    expect(deps.get('evil-env-stealer')).toMatchObject({
      version: '1.0.0',
      direct: true,
      isDev: false,
      installPath: path.join(SAMPLE, 'node_modules/evil-env-stealer'),
    });
    expect(deps.get('tiny-dep')).toMatchObject({
      version: '0.1.0',
      direct: false,
      via: ['clean-utils'],
      installPath: path.join(SAMPLE, 'node_modules/clean-utils/node_modules/tiny-dep'),
    });
    expect(deps.get('tiny-dep')?.declared?.name).toBe('clean-utils');
  });

  it('reports not-installed deps with the locked version and no install path', async () => {
    const dep = byName(await resolveFixture(SAMPLE)).get('not-installed');
    expect(dep).toMatchObject({ version: '4.2.1', direct: true });
    expect(dep?.installPath).toBeUndefined();
  });

  it('excludes dev deps unless asked', async () => {
    expect(byName(await resolveFixture(SAMPLE)).has('dev-only-tool')).toBe(false);
    const withDev = byName(await resolveFixture(SAMPLE, { includeDev: true }));
    expect(withDev.get('dev-only-tool')?.isDev).toBe(true);
  });

  it('skips transitive deps when disabled', async () => {
    const deps = byName(await resolveFixture(SAMPLE, { scanTransitive: false }));
    expect(deps.has('tiny-dep')).toBe(false);
    expect(deps.has('clean-utils')).toBe(true);
  });

  it('follows pnpm symlinks into the store', async () => {
    const dir = path.join(FIXTURES, 'npm-pnpm');
    const deps = byName(await resolveFixture(dir));
    expect(deps.get('pnpm-a')?.installPath).toBe(
      path.join(dir, 'node_modules/.pnpm/pnpm-a@1.0.0/node_modules/pnpm-a'),
    );
    expect(deps.get('pnpm-b')).toMatchObject({ version: '2.0.0', via: ['pnpm-a'] });
  });

  it('uses yarn lockfiles for deps that are not installed', async () => {
    for (const fixture of ['npm-yarn-classic', 'npm-yarn-berry']) {
      const deps = byName(await resolveFixture(path.join(FIXTURES, fixture)));
      expect(deps.get('yarn-a')?.version, fixture).toBe('1.2.3');
      expect(deps.get('yarn-missing')?.version, fixture).toBe('0.5.4');
    }
  });

  it('works without a lockfile and skips workspace-linked packages', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-nolock-'));
    await cp(path.join(FIXTURES, 'npm-yarn-classic'), dir, { recursive: true });
    const { rm, symlink, mkdir, writeFile } = await import('node:fs/promises');
    await rm(path.join(dir, 'yarn.lock'));
    await mkdir(path.join(dir, 'packages/local'), { recursive: true });
    await writeFile(path.join(dir, 'packages/local/package.json'), '{"version":"0.0.1"}');
    await symlink('../packages/local', path.join(dir, 'node_modules/local'));
    const pkg = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
    pkg.dependencies.local = 'workspace:*';
    await writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg));
    const deps = byName(await resolveFixture(dir));
    expect(deps.get('yarn-a')?.version).toBe('1.2.3');
    expect(deps.get('yarn-missing')?.version).toBe('~0.5.0');
    expect(deps.has('local')).toBe(false);
  });

  it('does not resolve packages outside the project root', async () => {
    expect(await locatePackage('typescript', SAMPLE, SAMPLE)).toBeUndefined();
  });

  it('stops when aborted', async () => {
    const signal = AbortSignal.abort();
    await expect(resolveFixture(SAMPLE, { signal })).rejects.toThrow();
  });
});

describe('npm adapter files', () => {
  it('matches project manifests only', () => {
    expect(npmAdapter.matches('/p/package.json')).toBe(true);
    expect(npmAdapter.matches('/p/node_modules/a/package.json')).toBe(false);
    expect(npmAdapter.matches('/p/package.json.bak')).toBe(false);
  });

  it('detects languages and skips type declarations', () => {
    expect(npmAdapter.languageOf('/a/index.mjs')).toBe('javascript');
    expect(npmAdapter.languageOf('/a/x.TS')).toBe('typescript');
    expect(npmAdapter.languageOf('/a/x.d.ts')).toBeUndefined();
    expect(npmAdapter.languageOf('/a/run.sh')).toBe('shell');
    expect(npmAdapter.languageOf('/a/package.json')).toBe('json');
    expect(npmAdapter.languageOf('/a/data.json')).toBeUndefined();
  });

  it('lists scannable files without nested node_modules', async () => {
    const dep = byName(await resolveFixture(SAMPLE)).get('clean-utils')!;
    const files = await npmAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.relative(dep.installPath!, f))).toEqual([
      'index.js',
      'package.json',
    ]);
    const stealer = byName(await resolveFixture(SAMPLE)).get('evil-env-stealer')!;
    const stealerFiles = await npmAdapter.listSourceFiles(stealer, DEFAULT_LIMITS);
    expect(stealerFiles.some((f) => f.endsWith('.d.ts'))).toBe(false);
  });

  it('honors file count and size limits', async () => {
    const dep = byName(await resolveFixture(SAMPLE)).get('evil-postinstall')!;
    expect(
      await npmAdapter.listSourceFiles(dep, { maxFilesPerPackage: 1, maxFileSizeBytes: 1e6 }),
    ).toHaveLength(1);
    expect(
      await npmAdapter.listSourceFiles(dep, { maxFilesPerPackage: 10, maxFileSizeBytes: 10 }),
    ).toEqual([]);
  });

  it('returns no files for packages that are not installed', async () => {
    const dep = byName(await resolveFixture(SAMPLE)).get('not-installed')!;
    expect(await npmAdapter.listSourceFiles(dep, DEFAULT_LIMITS)).toEqual([]);
  });
});
