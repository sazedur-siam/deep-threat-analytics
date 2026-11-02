import { mkdtemp, writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import {
  isPlatformPackage,
  normalizeComposerVersion,
  parseComposerJson,
  phpAdapter,
  readComposerLock,
} from '../../../src/adapters/php';
import { DEFAULT_LIMITS, type Finding, type ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';
import { scanInstallHooks } from '../../../src/scanners/installHooks';

const SAMPLE = path.resolve(__dirname, '../../fixtures/php-sample');
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };

async function resolve(dir = SAMPLE, over: Partial<AdapterContext> = {}) {
  const manifest = path.join(dir, 'composer.json');
  const declared = phpAdapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return phpAdapter.resolve(manifest, declared, { ...ctx, ...over });
}
const byName = (deps: ResolvedDep[]) => new Map(deps.map((d) => [d.name, d]));

describe('composer helpers', () => {
  it('recognizes platform packages', () => {
    for (const name of ['php', 'ext-json', 'lib-icu', 'composer-plugin-api', 'hhvm']) {
      expect(isPlatformPackage(name), name).toBe(true);
    }
    expect(isPlatformPackage('symfony/console')).toBe(false);
  });

  it('strips v prefixes from versions', () => {
    expect(normalizeComposerVersion('v5.4.0')).toBe('5.4.0');
    expect(normalizeComposerVersion('dev-main')).toBe('dev-main');
  });
});

describe('composer.json parsing', () => {
  it('reads require and require-dev without platform packages', async () => {
    const manifest = path.join(SAMPLE, 'composer.json');
    const text = await readFile(manifest, 'utf8');
    const deps = parseComposerJson(manifest, text);
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['evil/stealer', '^1.0', false],
      ['clean/str', '^2.0', false],
      ['acme/installer-plugin', '^1.0', false],
      ['missing/pkg', '1.0.3', false],
      ['phpunit/phpunit', '^10.0', true],
    ]);
    const lines = text.split('\n');
    const evil = deps[0]!;
    expect(lines[evil.range.startLine]!.slice(evil.range.startCol, evil.range.endCol)).toBe(
      'Evil/Stealer',
    );
    expect(deps[1]?.ignoredRules).toEqual(['network/*']);
  });

  it('supports "all" ignores and rejects malformed JSON', () => {
    const deps = parseComposerJson(
      '/p',
      '{"require":{"a/b":"1"},"extra":{"depthreat":{"ignore":{"a/b":"all"}}}}',
    );
    expect(deps[0]?.ignoredRules).toBe('all');
    expect(parseComposerJson('/p', '{"require": {')).toEqual([]);
    expect(parseComposerJson('/p', '{"require": []}')).toEqual([]);
  });
});

describe('composer resolve', () => {
  it('uses locked versions and vendor directories', async () => {
    const deps = byName(await resolve());
    expect(deps.get('evil/stealer')).toMatchObject({
      version: '1.0.0',
      direct: true,
      installPath: path.join(SAMPLE, 'vendor/evil/stealer'),
    });
    expect(deps.get('clean/str')?.version).toBe('2.1.0');
    expect(deps.get('missing/pkg')).toMatchObject({ version: '1.0.3' });
    expect(deps.get('missing/pkg')?.installPath).toBeUndefined();
    expect(deps.has('phpunit/phpunit')).toBe(false);
  });

  it('walks lock requirements for transitive packages', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-php-'));
    await writeFile(path.join(dir, 'composer.json'), '{"require":{"evil/stealer":"^1"}}');
    await writeFile(
      path.join(dir, 'composer.lock'),
      await readFile(path.join(SAMPLE, 'composer.lock'), 'utf8'),
    );
    const deps = byName(await resolve(dir));
    expect(deps.get('clean/str')).toMatchObject({ direct: false, via: ['evil/stealer'] });
    expect(byName(await resolve(dir, { scanTransitive: false })).has('clean/str')).toBe(false);
  });

  it('honors vendor-dir, dev dependencies and missing lockfiles', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'depthreat-php-'));
    await writeFile(
      path.join(dir, 'composer.json'),
      '{"require":{"a/b":"v1.2.0","c/d":"^2"},"require-dev":{"e/f":"1.0"},"config":{"vendor-dir":"lib"}}',
    );
    const deps = await resolve(dir, { includeDev: true });
    expect(deps.map((d) => [d.name, d.version, d.isDev])).toEqual([
      ['a/b', '1.2.0', false],
      ['c/d', 'unknown', false],
      ['e/f', '1.0', true],
    ]);
    expect(await readComposerLock(path.join(dir, 'composer.lock'))).toEqual(new Map());
  });

  it('stops when aborted', async () => {
    await expect(resolve(SAMPLE, { signal: AbortSignal.abort() })).rejects.toThrow();
  });
});

describe('composer files', () => {
  it('matches project manifests only and detects languages', () => {
    expect(phpAdapter.matches('/p/composer.json')).toBe(true);
    expect(phpAdapter.matches('/p/vendor/a/b/composer.json')).toBe(false);
    expect(phpAdapter.languageOf('/a/x.phtml')).toBe('php');
    expect(phpAdapter.languageOf('/a/composer.json')).toBe('json');
    expect(phpAdapter.languageOf('/a/x.twig')).toBeUndefined();
    expect(phpAdapter.languageOf('/a/x.sh')).toBe('shell');
  });

  it('lists sources without tests', async () => {
    const dep = byName(await resolve()).get('clean/str')!;
    const files = await phpAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.relative(dep.installPath!, f))).toEqual([
      'composer.json',
      path.join('src', 'Str.php'),
    ]);
    const missing = byName(await resolve()).get('missing/pkg')!;
    expect(await phpAdapter.listSourceFiles(missing, DEFAULT_LIMITS)).toEqual([]);
  });
});

describe('php fixture end to end', () => {
  const findings = new Map<string, Finding[]>();

  beforeAll(async () => {
    const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
      compileRule,
    );
    for (const dep of await resolve()) {
      const files = await phpAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
      findings.set(dep.name, [
        ...(await scanPackageCode({
          dep,
          files,
          languageOf: phpAdapter.languageOf,
          rules,
          maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
        })),
        ...(await scanInstallHooks(dep, files)),
      ]);
    }
  });

  const ids = (name: string) => (findings.get(name) ?? []).map((f) => f.ruleId).sort();

  it('flags environment exfiltration', () => {
    expect(ids('evil/stealer')).toEqual([
      'env-access/php-environ',
      'exfiltration/php-env-to-network',
    ]);
  });

  it('flags the plugin as an install hook and its hidden eval', () => {
    expect(ids('acme/installer-plugin')).toEqual([
      'dynamic-code/php-decode-execute',
      'install-hook/composer-plugin',
    ]);
    const plugin = findings
      .get('acme/installer-plugin')!
      .find((f) => f.ruleId === 'install-hook/composer-plugin')!;
    expect(plugin.severity).toBe('medium');
  });

  it('reports nothing for clean packages, including their tests', () => {
    expect(ids('clean/str')).toEqual([]);
    expect(ids('missing/pkg')).toEqual([]);
  });
});
