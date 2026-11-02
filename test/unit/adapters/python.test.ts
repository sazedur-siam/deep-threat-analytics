import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import { createPythonAdapter, pythonAdapter, readPythonLock } from '../../../src/adapters/python';
import {
  findSitePackages,
  indexDists,
  parseMetadata,
  parseRecord,
  SITE_PACKAGES_SCRIPT,
} from '../../../src/adapters/python/dists';
import { parsePyproject, parseRequirementsTxt } from '../../../src/adapters/python/manifests';
import {
  normalizePythonName,
  parseIgnoreMarker,
  parseRequirement,
  pinnedVersion,
} from '../../../src/adapters/python/names';
import { DEFAULT_LIMITS, type ResolvedDep } from '../../../src/core/types';

const SAMPLE = path.resolve(__dirname, '../../fixtures/py-sample');
const SITE = path.join(SAMPLE, '.venv/lib/python3.12/site-packages');
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };

async function resolveSample(file = 'requirements.txt', overrides: Partial<AdapterContext> = {}) {
  const manifest = path.join(SAMPLE, file);
  const declared = pythonAdapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return pythonAdapter.resolve(manifest, declared, { ...ctx, ...overrides });
}

const byName = (deps: ResolvedDep[]) => new Map(deps.map((d) => [d.name, d]));

describe('names', () => {
  it('normalizes per PEP 503', () => {
    expect(normalizePythonName('Foo__Bar.baz')).toBe('foo-bar-baz');
  });

  it('parses ignore markers', () => {
    expect(parseIgnoreMarker(' depthreat-ignore')).toBe('all');
    expect(parseIgnoreMarker('depthreat-ignore[a/b, c/*]')).toEqual(['a/b', 'c/*']);
    expect(parseIgnoreMarker('depthreat-ignore[ ]')).toBe('all');
    expect(parseIgnoreMarker('pinned for py3.8')).toBeUndefined();
  });

  it('extracts pinned versions', () => {
    expect(pinnedVersion('==1.2.3')).toBe('1.2.3');
    expect(pinnedVersion('>=1,==1.2.3')).toBe('1.2.3');
    expect(pinnedVersion('===2.0')).toBe('2.0');
    expect(pinnedVersion('>=1')).toBeUndefined();
    expect(pinnedVersion('==1.*')).toBeUndefined();
  });

  it('parses PEP 508 requirements', () => {
    expect(parseRequirement('  requests[socks, security] (>=2.0) ; python_version>"3.8"')).toEqual({
      name: 'requests',
      extras: ['socks', 'security'],
      spec: '>=2.0',
      marker: 'python_version>"3.8"',
      nameStart: 2,
      nameEnd: 10,
    });
    expect(parseRequirement('pkg @ https://example.invalid/p.whl')?.spec).toBe(
      '@ https://example.invalid/p.whl',
    );
    expect(parseRequirement('-e .')).toBeUndefined();
  });
});

describe('requirements.txt', () => {
  const text = [
    '# comment',
    'Evil_Pkg==1.0  # depthreat-ignore[exec/*]',
    'long-name>=1 \\',
    '    ; python_version >= "3.8"',
    '-r base.txt',
    'https://example.invalid/x.whl',
    './local',
    'named @ https://example.invalid/n.whl',
    '',
  ].join('\r\n');
  const deps = parseRequirementsTxt('/p/requirements.txt', text);

  it('collects requirements with normalized names and specs', () => {
    expect(deps.map((d) => [d.name, d.versionSpec])).toEqual([
      ['evil-pkg', '==1.0'],
      ['long-name', '>=1'],
      ['named', '@ https://example.invalid/n.whl'],
    ]);
  });

  it('ranges cover the original name', () => {
    expect(deps[0]?.range).toEqual({ startLine: 1, startCol: 0, endLine: 1, endCol: 8 });
    expect(deps[1]?.range.startLine).toBe(2);
    expect(deps[2]?.range.startLine).toBe(7);
  });

  it('reads inline ignores and dev file names', () => {
    expect(deps[0]?.ignoredRules).toEqual(['exec/*']);
    expect(deps[0]?.isDev).toBe(false);
    expect(parseRequirementsTxt('/p/requirements-dev.txt', 'a')[0]?.isDev).toBe(true);
    expect(parseRequirementsTxt('/p/test-requirements.txt', 'a')[0]?.isDev).toBe(true);
    expect(parseRequirementsTxt('/p/requirements-prod.txt', 'a')[0]?.isDev).toBe(false);
  });
});

describe('pyproject.toml', () => {
  it('parses PEP 621, optional deps, poetry tables and dependency groups', async () => {
    const manifest = path.join(SAMPLE, 'pyproject.toml');
    const text = await readFile(manifest, 'utf8');
    const deps = parsePyproject(manifest, text);
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['evil-exfil', '==1.0.0', false],
      ['clean-lib', '>=2', false],
      ['requests', '>=2.0', false],
      ['old-egg', '1.0', false],
      ['pytest', '^8.0', true],
      ['sphinx', '', true],
      ['ruff', '>=0.4', true],
    ]);
    expect(deps[1]?.ignoredRules).toBe('all');
    const lines = text.split('\n');
    for (const d of deps) {
      const line = lines[d.range.startLine]!;
      expect(normalizePythonName(line.slice(d.range.startCol, d.range.endCol))).toBe(d.name);
    }
  });

  it('handles single-line arrays and returns nothing for invalid TOML', () => {
    const deps = parsePyproject('/p', '[project]\ndependencies = ["a>=1", \'b\']\n[other]\nx = 1');
    expect(deps.map((d) => d.name)).toEqual(['a', 'b']);
    expect(parsePyproject('/p', '[project\ndependencies = [')).toEqual([]);
  });
});

describe('dist metadata', () => {
  it('parses RECORD rows including quoted paths', () => {
    expect(parseRecord('a.py,sha,1\n"b,c.py",,\n\n')).toEqual(['a.py', 'b,c.py']);
  });

  it('parses metadata headers and skips extras and the description body', () => {
    const meta = parseMetadata(
      'Name: X\nVersion: 2\nRequires-Dist: Foo_Bar (>=1)\nRequires-Dist: y ; extra == "z"\n\nRequires-Dist: body',
    );
    expect(meta).toEqual({ name: 'X', version: '2', requires: ['foo-bar'] });
  });

  it('indexes dist-info and egg-info distributions', async () => {
    const dists = await indexDists([SITE, path.join(SAMPLE, 'missing')]);
    expect([...dists.keys()].sort()).toEqual([
      'clean-lib',
      'evil-exfil',
      'evil-setup',
      'old-egg',
      'tiny-py-dep',
    ]);
    expect(dists.get('clean-lib')).toMatchObject({ version: '2.1.0', requires: ['tiny-py-dep'] });
    expect(dists.get('old-egg')?.files).toContain(path.join('old_egg', '__init__.py'));
  });

  it('reads poetry.lock versions', async () => {
    const locked = await readPythonLock(SAMPLE);
    expect(locked.get('not-installed-py')).toBe('9.9.9');
    expect(await readPythonLock(path.join(SAMPLE, 'missing'))).toEqual(new Map());
  });
});

describe('site-packages discovery', () => {
  it('uses a venv on disk without running anything', async () => {
    const runner = vi.fn();
    expect(await findSitePackages(SAMPLE, { trusted: true, runner })).toEqual([SITE]);
    expect(runner).not.toHaveBeenCalled();
  });

  it('never spawns a process in untrusted workspaces', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-py-'));
    const runner = vi.fn();
    expect(await findSitePackages(dir, { trusted: false, interpreter: 'py', runner })).toEqual([]);
    expect(runner).not.toHaveBeenCalled();
  });

  it('asks the interpreter in isolated mode when trusted', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-py-'));
    const runner = vi.fn(async () => JSON.stringify([SITE, '/does/not/exist']));
    const dirs = await findSitePackages(dir, { trusted: true, interpreter: '/x/python', runner });
    expect(dirs).toEqual([SITE]);
    expect(runner).toHaveBeenCalledWith(
      '/x/python',
      ['-I', '-c', SITE_PACKAGES_SCRIPT],
      expect.objectContaining({ timeoutMs: 10_000 }),
    );
  });

  it('falls back quietly when the interpreter fails or prints junk', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-py-'));
    const failing = vi.fn(async () => {
      throw new Error('not found');
    });
    expect(await findSitePackages(dir, { trusted: true, runner: failing })).toEqual([]);
    expect(failing).toHaveBeenCalledWith('python3', expect.anything(), expect.anything());
    const junk = vi.fn(async () => '{"not": "a list"}');
    expect(await findSitePackages(dir, { trusted: true, runner: junk })).toEqual([]);
  });

  it('finds Windows-style venv layouts', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-py-'));
    await mkdir(path.join(dir, 'venv/Lib/site-packages'), { recursive: true });
    await writeFile(path.join(dir, 'venv/pyvenv.cfg'), '');
    expect(await findSitePackages(dir, { trusted: false, runner: vi.fn() })).toEqual([
      path.join(dir, 'venv/Lib/site-packages'),
    ]);
  });
});

describe('python resolve', () => {
  it('resolves installed versions, lockfile and pinned fallbacks', async () => {
    const deps = byName(await resolveSample());
    expect(deps.get('evil-exfil')).toMatchObject({ version: '1.0.0', installPath: SITE });
    // Installed 2.1.0 wins over the lockfile's 2.0.9: that is the code being scanned.
    expect(deps.get('clean-lib')?.version).toBe('2.1.0');
    expect(deps.get('not-installed-py')).toMatchObject({ version: '9.9.9', direct: true });
    expect(deps.get('not-installed-py')?.installPath).toBeUndefined();
    expect(deps.get('evil-setup')?.declared?.ignoredRules).toEqual(['exec/python-shell']);
  });

  it('walks Requires-Dist for transitive deps', async () => {
    const deps = byName(await resolveSample());
    expect(deps.get('tiny-py-dep')).toMatchObject({
      direct: false,
      version: '0.1.0',
      via: ['clean-lib'],
    });
    expect(deps.has('fast-extra')).toBe(false);
    const direct = byName(await resolveSample('requirements.txt', { scanTransitive: false }));
    expect(direct.has('tiny-py-dep')).toBe(false);
  });

  it('includes dev groups only when asked', async () => {
    expect(byName(await resolveSample('pyproject.toml')).has('pytest')).toBe(false);
    const withDev = byName(await resolveSample('pyproject.toml', { includeDev: true }));
    expect(withDev.get('pytest')).toMatchObject({ isDev: true, version: 'unknown' });
  });

  it('uses the injected runner only when trusted and no venv exists', async () => {
    const runProcess = vi.fn(async () => JSON.stringify([SITE]));
    const adapter = createPythonAdapter({ runProcess });
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-py-'));
    const manifest = path.join(dir, 'requirements.txt');
    const declared = adapter.parseManifest(manifest, 'clean-lib');
    const trusted = await adapter.resolve(manifest, declared, { ...ctx, trusted: true });
    expect(trusted[0]?.installPath).toBe(SITE);
    const untrusted = await adapter.resolve(manifest, declared, ctx);
    expect(untrusted[0]?.installPath).toBeUndefined();
    expect(runProcess).toHaveBeenCalledTimes(1);
  });

  it('stops when aborted', async () => {
    await expect(
      resolveSample('requirements.txt', { signal: AbortSignal.abort() }),
    ).rejects.toThrow();
  });
});

describe('python adapter files', () => {
  it('matches project manifests only', () => {
    expect(pythonAdapter.matches('/p/requirements.txt')).toBe(true);
    expect(pythonAdapter.matches('/p/requirements-dev.txt')).toBe(true);
    expect(pythonAdapter.matches('/p/pyproject.toml')).toBe(true);
    expect(pythonAdapter.matches('/p/.venv/lib/x/pyproject.toml')).toBe(false);
    expect(pythonAdapter.matches('/p/setup.cfg')).toBe(false);
  });

  it('detects languages', () => {
    expect(pythonAdapter.languageOf('/a/x.py')).toBe('python');
    expect(pythonAdapter.languageOf('/a/x.pth')).toBe('python');
    expect(pythonAdapter.languageOf('/a/run.sh')).toBe('shell');
    expect(pythonAdapter.languageOf('/a/x.pyc')).toBeUndefined();
  });

  it('lists files from RECORD, including .pth and skipping caches and outside paths', async () => {
    const deps = byName(await resolveSample());
    const files = async (name: string) =>
      (await pythonAdapter.listSourceFiles(deps.get(name)!, DEFAULT_LIMITS)).map((f) =>
        path.relative(SITE, f),
      );
    expect(await files('evil-setup')).toEqual(['evil_setup/__init__.py', 'evil_setup_hook.pth']);
    expect(await files('evil-exfil')).toEqual(['evil_exfil/__init__.py']);
    expect(await files('clean-lib')).toEqual(['clean_lib/__init__.py']);
  });

  it('falls back to top_level.txt when RECORD is missing', async () => {
    const dep = byName(await resolveSample()).get('tiny-py-dep')!;
    const files = await pythonAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.relative(SITE, f))).toEqual(['tiny_py_dep.py']);
  });

  it('honors limits and handles missing installs', async () => {
    const deps = byName(await resolveSample());
    const limited = { maxFilesPerPackage: 1, maxFileSizeBytes: 1e6 };
    expect(await pythonAdapter.listSourceFiles(deps.get('evil-setup')!, limited)).toHaveLength(1);
    const tiny = { maxFilesPerPackage: 10, maxFileSizeBytes: 5 };
    expect(await pythonAdapter.listSourceFiles(deps.get('evil-setup')!, tiny)).toEqual([]);
    expect(
      await pythonAdapter.listSourceFiles(deps.get('not-installed-py')!, DEFAULT_LIMITS),
    ).toEqual([]);
    const ghost = { ...deps.get('evil-exfil')!, name: 'ghost' };
    expect(await pythonAdapter.listSourceFiles(ghost, DEFAULT_LIMITS)).toEqual([]);
  });
});
