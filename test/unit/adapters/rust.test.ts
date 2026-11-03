import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import {
  createRustAdapter,
  defaultCargoHome,
  findCargoLock,
  parseCargoToml,
  readCargoLock,
} from '../../../src/adapters/rust';
import { DEFAULT_LIMITS, type Finding, type ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';
import { scanInstallHooks } from '../../../src/scanners/installHooks';

const SAMPLE = path.resolve(__dirname, '../../fixtures/rust-sample');
const HOME = path.join(SAMPLE, '.cargo-home');
const SRC = path.join(HOME, 'registry/src/index.crates.io-0000000000000000');
const rust = createRustAdapter({ cargoHome: HOME });
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };

async function resolve(over: Partial<AdapterContext> = {}) {
  const manifest = path.join(SAMPLE, 'Cargo.toml');
  const declared = rust.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return rust.resolve(manifest, declared, { ...ctx, ...over });
}
const byName = (deps: ResolvedDep[]) => new Map(deps.map((d) => [d.name, d]));

describe('Cargo.toml parsing', () => {
  it('reads every dependency table, renames, sub-tables and skips path crates', async () => {
    const manifest = path.join(SAMPLE, 'Cargo.toml');
    const text = await readFile(manifest, 'utf8');
    const deps = parseCargoToml(manifest, text);
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['evil-telemetry', '1.0', false],
      ['clean-math', '0.3', false],
      ['real-name', '2', false],
      ['missing-crate', '0.1', false],
      ['table-dep', '1.2', false],
      ['shady-build', '0.1', false],
      ['test-helper', '1', true],
    ]);
    const lines = text.split('\n');
    const renamed = deps.find((d) => d.name === 'real-name')!;
    expect(
      lines[renamed.range.startLine]!.slice(renamed.range.startCol, renamed.range.endCol),
    ).toBe('renamed');
    expect(deps.find((d) => d.name === 'missing-crate')?.ignoredRules).toEqual(['network/*']);
  });

  it('handles target-specific and workspace tables, and rejects invalid TOML', () => {
    const deps = parseCargoToml(
      '/p/Cargo.toml',
      '[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n[workspace.dependencies]\nserde = { version = "1" }\n[dependencies.local]\npath = "../x"\n[features]\ndefault = []',
    );
    expect(deps.map((d) => d.name)).toEqual(['libc', 'serde']);
    expect(parseCargoToml('/p', '[dependencies\nx = ')).toEqual([]);
  });
});

describe('Cargo.lock', () => {
  it('reads packages and finds the lockfile upwards', async () => {
    const file = findCargoLock(path.join(SAMPLE, 'src'))!;
    expect(file).toBe(path.join(SAMPLE, 'Cargo.lock'));
    const lock = await readCargoLock(file);
    expect(lock.find((p) => p.name === 'evil-telemetry')).toMatchObject({
      version: '1.0.0',
      dependencies: ['clean-math 0.3.1', 'local-crate'],
    });
    expect(lock.find((p) => p.name === 'local-crate')?.source).toBeUndefined();
    expect(await readCargoLock(path.join(SAMPLE, 'missing.lock'))).toEqual([]);
  });

  it('finds CARGO_HOME', () => {
    expect(defaultCargoHome({ CARGO_HOME: '/c' })).toBe('/c');
    expect(defaultCargoHome({})).toMatch(/\.cargo$/);
  });
});

describe('cargo resolve', () => {
  it('uses locked versions and the registry cache', async () => {
    const deps = byName(await resolve());
    expect(deps.get('evil-telemetry')).toMatchObject({
      version: '1.0.0',
      direct: true,
      installPath: path.join(SRC, 'evil-telemetry-1.0.0'),
    });
    expect(deps.get('real-name')?.installPath).toBe(path.join(SRC, 'real-name-2.0.0'));
    expect(deps.get('missing-crate')).toMatchObject({ version: '0.1.4' });
    expect(deps.get('missing-crate')?.installPath).toBeUndefined();
    expect(deps.has('local-crate')).toBe(false);
    expect(deps.has('test-helper')).toBe(false);
  });

  it('walks the lock graph for transitive crates', async () => {
    const deps = await resolve();
    // clean-math is also a direct dependency, so it is reported once, as direct.
    expect(deps.filter((d) => d.name === 'clean-math')).toHaveLength(1);
    const direct = byName(await resolve({ scanTransitive: false }));
    expect(direct.size).toBe(6);
  });

  it('reports transitive crates with their path', async () => {
    const manifest = '/virtual/Cargo.toml';
    const declared = parseCargoToml(manifest, '[dependencies]\nevil-telemetry = "1"');
    const lockDir = SAMPLE;
    const adapter = createRustAdapter({ cargoHome: HOME });
    const deps = await adapter.resolve(path.join(lockDir, 'Cargo.toml'), declared, ctx);
    expect(byName(deps).get('clean-math')).toMatchObject({
      direct: false,
      via: ['evil-telemetry'],
      version: '0.3.1',
    });
  });

  it('includes dev dependencies when asked and falls back without a lockfile', async () => {
    expect(byName(await resolve({ includeDev: true })).get('test-helper')?.isDev).toBe(true);
    const adapter = createRustAdapter({ cargoHome: path.join(SAMPLE, 'nope') });
    const declared = parseCargoToml('/tmp/x/Cargo.toml', '[dependencies]\na = "1.2.3"\nb = "^1"');
    const deps = await adapter.resolve('/tmp/x/Cargo.toml', declared, ctx);
    expect(deps.map((d) => d.version)).toEqual(['1.2.3', 'unknown']);
  });

  it('stops when aborted', async () => {
    await expect(resolve({ signal: AbortSignal.abort() })).rejects.toThrow();
  });
});

describe('cargo files', () => {
  it('matches only project manifests', () => {
    expect(rust.matches('/p/Cargo.toml')).toBe(true);
    expect(rust.matches('/p/vendor/x/Cargo.toml')).toBe(false);
    expect(rust.matches('/p/target/x/Cargo.toml')).toBe(false);
    expect(rust.matches('/h/.cargo/registry/src/i/x-1/Cargo.toml')).toBe(false);
    expect(rust.matches('/p/Cargo.lock')).toBe(false);
  });

  it('lists sources without tests, and detects languages', async () => {
    const dep = byName(await resolve()).get('clean-math')!;
    const files = await rust.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.relative(dep.installPath!, f))).toEqual([
      path.join('src', 'lib.rs'),
    ]);
    expect(rust.languageOf('/x/run.sh')).toBe('shell');
    expect(rust.languageOf('/x/Cargo.toml')).toBeUndefined();
    const missing = byName(await resolve()).get('missing-crate')!;
    expect(await rust.listSourceFiles(missing, DEFAULT_LIMITS)).toEqual([]);
  });
});

describe('rust fixture end to end', () => {
  const findings = new Map<string, Finding[]>();

  beforeAll(async () => {
    const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
      compileRule,
    );
    for (const dep of await resolve()) {
      const files = await rust.listSourceFiles(dep, DEFAULT_LIMITS);
      findings.set(dep.name, [
        ...(await scanPackageCode({
          dep,
          files,
          languageOf: rust.languageOf,
          rules,
          maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
        })),
        ...(await scanInstallHooks(dep, files)),
      ]);
    }
  });

  const ids = (name: string) => (findings.get(name) ?? []).map((f) => f.ruleId).sort();

  it('flags environment exfiltration', () => {
    expect(ids('evil-telemetry')).toEqual([
      'env-access/rust-env-vars',
      'exfiltration/rust-env-to-network',
    ]);
  });

  it('flags the malicious build script as a high-severity install hook', () => {
    expect(ids('shady-build')).toEqual([
      'dynamic-code/download-and-execute',
      'exec/rust-shell',
      'install-hook/cargo-build-script',
    ]);
    const hook = findings
      .get('shady-build')!
      .find((f) => f.ruleId === 'install-hook/cargo-build-script')!;
    expect(hook.severity).toBe('high');
    expect(hook.title).toBe('Build script runs commands or network code');
  });

  it('reports nothing for clean crates', () => {
    for (const name of ['clean-math', 'real-name', 'table-dep', 'missing-crate']) {
      expect(ids(name), name).toEqual([]);
    }
  });
});

describe('build script severities', () => {
  const dep: ResolvedDep = {
    ecosystem: 'cargo',
    name: 'c',
    version: '1.0.0',
    installPath: '/c',
    direct: true,
    isDev: false,
  };
  const severity = async (code: string) =>
    (await scanInstallHooks(dep, ['/c/build.rs'], async () => code))[0]?.severity;

  it('rates plain, shell and network build scripts', async () => {
    expect(await severity('fn main() { cc::Build::new().file("x.c").compile("x"); }')).toBe('low');
    expect(await severity('fn main() {\n  Command::new("bash").status();\n}')).toBe('medium');
    expect(await severity('// reqwest::get(u)\nfn main() {}')).toBe('low');
    expect(await severity('fn main() {\n Command::new("sh");\n let h = env::var("HOME");\n}')).toBe(
      'high',
    );
    expect(await scanInstallHooks(dep, ['/c/src/build.rs'], async () => 'reqwest::get(u)')).toEqual(
      [],
    );
  });
});
