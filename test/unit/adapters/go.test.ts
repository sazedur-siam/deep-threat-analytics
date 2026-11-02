import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import {
  createGoAdapter,
  defaultModCache,
  escapeModulePath,
  parseGoModFile,
} from '../../../src/adapters/golang';
import { DEFAULT_LIMITS, type Finding, type ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';

const FIXTURES = path.resolve(__dirname, '../../fixtures');
const SAMPLE = path.join(FIXTURES, 'go-sample');
const CACHE = path.join(SAMPLE, '.gomodcache');
const go = createGoAdapter({ modCache: CACHE });
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };

async function resolve(dir: string, over: Partial<AdapterContext> = {}) {
  const manifest = path.join(dir, 'go.mod');
  const declared = go.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return go.resolve(manifest, declared, { ...ctx, ...over });
}
const byName = (deps: ResolvedDep[]) => new Map(deps.map((d) => [d.name, d]));

describe('go.mod parsing', () => {
  it('reads require blocks, single requires, indirect markers and replaces', async () => {
    const text = await readFile(path.join(SAMPLE, 'go.mod'), 'utf8');
    const { requires, replaces } = parseGoModFile(text);
    expect(requires.map((r) => [r.path, r.version, r.indirect])).toEqual([
      ['github.com/EvilCorp/beacon', 'v1.0.0', false],
      ['github.com/clean/strutil', 'v0.2.0', true],
      ['github.com/missing/mod', 'v1.0.0', false],
      ['github.com/old/name', 'v1.0.0', false],
      ['example.invalid/local', 'v0.0.0', false],
    ]);
    expect(replaces).toEqual([
      { from: 'example.invalid/local', to: { path: '../local' } },
      {
        from: 'github.com/old/name@v1.0.0',
        to: { path: 'github.com/new/name', version: 'v1.2.3' },
      },
    ]);
  });

  it('builds declared deps with ranges and inline ignores', async () => {
    const manifest = path.join(SAMPLE, 'go.mod');
    const text = await readFile(manifest, 'utf8');
    const deps = go.parseManifest(manifest, text);
    const lines = text.split('\n');
    for (const d of deps) {
      expect(lines[d.range.startLine]!.slice(d.range.startCol, d.range.endCol)).toBe(d.name);
    }
    expect(deps.find((d) => d.name === 'github.com/missing/mod')?.ignoredRules).toEqual([
      'network/*',
    ]);
    expect(deps.every((d) => d.ecosystem === 'go' && !d.isDev)).toBe(true);
  });

  it('ignores comments, blank lines and other directives', () => {
    const { requires } = parseGoModFile(
      'module x\n// require fake v1\n\nexclude a v1\nrequire b v2 // c',
    );
    expect(requires.map((r) => r.path)).toEqual(['b']);
  });
});

describe('module cache paths', () => {
  it('escapes upper-case letters', () => {
    expect(escapeModulePath('github.com/EvilCorp/Beacon')).toBe('github.com/!evil!corp/!beacon');
  });

  it('finds the cache from GOMODCACHE, GOPATH or the home directory', () => {
    expect(defaultModCache({ GOMODCACHE: '/cache' })).toBe('/cache');
    expect(defaultModCache({ GOPATH: `/gp${path.delimiter}/other` })).toBe(
      path.join('/gp', 'pkg', 'mod'),
    );
    expect(defaultModCache({})).toMatch(/go[\\/]pkg[\\/]mod$/);
  });
});

describe('go resolve', () => {
  it('locates modules in the cache, applies replaces and skips local ones', async () => {
    const deps = byName(await resolve(SAMPLE));
    expect(deps.get('github.com/EvilCorp/beacon')).toMatchObject({
      version: 'v1.0.0',
      direct: true,
      installPath: path.join(CACHE, 'github.com/!evil!corp/beacon@v1.0.0'),
    });
    expect(deps.get('github.com/new/name')).toMatchObject({
      version: 'v1.2.3',
      installPath: path.join(CACHE, 'github.com/new/name@v1.2.3'),
    });
    expect(deps.get('github.com/new/name')?.declared?.name).toBe('github.com/old/name');
    expect(deps.get('github.com/missing/mod')?.installPath).toBeUndefined();
    expect(deps.has('example.invalid/local')).toBe(false);
  });

  it('treats indirect requirements as transitive', async () => {
    expect(byName(await resolve(SAMPLE)).get('github.com/clean/strutil')?.direct).toBe(false);
    const direct = byName(await resolve(SAMPLE, { scanTransitive: false }));
    expect(direct.has('github.com/clean/strutil')).toBe(false);
  });

  it('prefers the vendor directory when present', async () => {
    const dir = path.join(FIXTURES, 'go-vendor');
    const [dep] = await resolve(dir);
    expect(dep?.installPath).toBe(path.join(dir, 'vendor/github.com/vendored/shell'));
  });

  it('stops when aborted', async () => {
    await expect(resolve(SAMPLE, { signal: AbortSignal.abort() })).rejects.toThrow();
  });
});

describe('go files', () => {
  it('matches only project go.mod files', () => {
    expect(go.matches('/p/go.mod')).toBe(true);
    expect(go.matches('/p/vendor/x/go.mod')).toBe(false);
    expect(go.matches('/home/u/go/pkg/mod/x@v1/go.mod')).toBe(false);
    expect(go.matches('/p/testdata/go.mod')).toBe(false);
    expect(go.matches('/p/go.sum')).toBe(false);
  });

  it('lists Go sources without tests or testdata', async () => {
    const dep = byName(await resolve(SAMPLE)).get('github.com/clean/strutil')!;
    const files = await go.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.basename(f))).toEqual(['strutil.go']);
    expect(go.languageOf('/a/run.sh')).toBe('shell');
    expect(go.languageOf('/a/x.s')).toBeUndefined();
    const missing = byName(await resolve(SAMPLE)).get('github.com/missing/mod')!;
    expect(await go.listSourceFiles(missing, DEFAULT_LIMITS)).toEqual([]);
  });
});

describe('go fixtures end to end', () => {
  const findings = new Map<string, Finding[]>();

  beforeAll(async () => {
    const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
      compileRule,
    );
    for (const dir of [SAMPLE, path.join(FIXTURES, 'go-vendor')]) {
      for (const dep of await resolve(dir)) {
        const files = await go.listSourceFiles(dep, DEFAULT_LIMITS);
        findings.set(
          dep.name,
          await scanPackageCode({
            dep,
            files,
            languageOf: go.languageOf,
            rules,
            maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
          }),
        );
      }
    }
  });

  const ids = (name: string) => (findings.get(name) ?? []).map((f) => f.ruleId).sort();

  it('flags the beacon that phones home on import', () => {
    expect(ids('github.com/EvilCorp/beacon')).toEqual([
      'env-access/go-environ',
      'exfiltration/go-env-to-network',
      'network/go-init-network',
    ]);
  });

  it('flags the vendored shell runner and nothing in clean modules', () => {
    expect(ids('github.com/vendored/shell')).toEqual(['exec/go-shell']);
    expect(ids('github.com/clean/strutil')).toEqual([]);
    expect(ids('github.com/new/name')).toEqual([]);
  });
});
