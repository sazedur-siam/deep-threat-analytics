import { existsSync } from 'node:fs';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { AdapterContext } from '../../../src/adapters/adapter';
import { createJavaAdapter, defaultJavaLocations } from '../../../src/adapters/java';
import { extractJar, safeEntryPath } from '../../../src/adapters/java/jar';
import {
  interpolate,
  parseGradle,
  parsePom,
  parsePomDependencies,
  pomProperties,
} from '../../../src/adapters/java/manifests';
import { DEFAULT_LIMITS, type Finding, type ResolvedDep } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';

const FIXTURES = path.resolve(__dirname, '../../fixtures');
const SAMPLE = path.join(FIXTURES, 'java-sample');
const M2 = path.join(SAMPLE, '.m2/repository');
const GRADLE = path.join(FIXTURES, 'java-gradle');
const ctx: AdapterContext = { trusted: false, includeDev: false, scanTransitive: true };

let extractRoot: string;
let java: ReturnType<typeof createJavaAdapter>;

beforeAll(async () => {
  extractRoot = await mkdtemp(path.join(tmpdir(), 'depthreat-java-'));
  java = createJavaAdapter({
    m2Repo: M2,
    gradleCache: path.join(GRADLE, '.gradle-cache/files-2.1'),
    extractRoot,
  });
});

async function resolve(manifest: string, over: Partial<AdapterContext> = {}) {
  const declared = java.parseManifest(manifest, await readFile(manifest, 'utf8'));
  return java.resolve(manifest, declared, { ...ctx, ...over });
}
const byName = (deps: ResolvedDep[]) => new Map(deps.map((d) => [d.name, d]));

describe('pom.xml parsing', () => {
  it('reads dependencies with properties, managed versions, scopes and ignores', async () => {
    const file = path.join(SAMPLE, 'pom.xml');
    const xml = await readFile(file, 'utf8');
    const deps = parsePom(file, xml);
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['com.evil:telemetry', '1.0.0', false],
      ['org.clean:util', '1.5.0', false],
      ['com.evil:zipslip', '1.0', false],
      ['com.missing:lib', '3.1.0', false],
      ['junit:junit', '4.13.2', true],
    ]);
    const lines = xml.split('\n');
    for (const d of deps) {
      const artifact = d.name.split(':')[1];
      expect(lines[d.range.startLine]!.slice(d.range.startCol, d.range.endCol)).toBe(artifact);
    }
    expect(deps[1]?.ignoredRules).toEqual(['network/*']);
  });

  it('interpolates project properties and leaves unknown ones unresolved', () => {
    const props = pomProperties(
      '<project><parent><version>9</version></parent><groupId>g</groupId><version>2.0</version><properties><a>1</a><b>${a}.5</b></properties></project>',
    );
    expect(interpolate('${b}', props)).toBe('1.5');
    expect(interpolate('${project.version}', props)).toBe('2.0');
    expect(props.get('project.parent.version')).toBe('9');
    expect(interpolate('${missing}', props)).toBeUndefined();
    expect(interpolate(undefined, props)).toBeUndefined();
  });

  it('marks optional dependencies and skips incomplete ones', () => {
    const deps = parsePomDependencies(
      '<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><optional>true</optional></dependency><dependency><groupId>x</groupId></dependency></dependencies></project>',
    );
    expect(deps).toHaveLength(1);
    expect(deps[0]).toMatchObject({ optional: true });
    expect(deps[0]?.version).toBeUndefined();
  });
});

describe('Gradle parsing', () => {
  it('reads string and map notation, skipping platforms and projects', async () => {
    const file = path.join(GRADLE, 'build.gradle');
    const text = await readFile(file, 'utf8');
    const deps = parseGradle(file, text);
    expect(deps.map((d) => [d.name, d.versionSpec, d.isDev])).toEqual([
      ['com.evil:telemetry', '1.0.0', false],
      ['org.clean:util', '1.5.0', false],
      ['org.dynamic:lib', '', false],
      ['junit:junit', '4.13.2', true],
    ]);
    const lines = text.split('\n');
    expect(
      lines[deps[0]!.range.startLine]!.slice(deps[0]!.range.startCol, deps[0]!.range.endCol),
    ).toBe('com.evil:telemetry');
    expect(
      lines[deps[1]!.range.startLine]!.slice(deps[1]!.range.startCol, deps[1]!.range.endCol),
    ).toBe('util');
    expect(deps[1]?.ignoredRules).toBe('all');
  });

  it('reads the Kotlin DSL', () => {
    const deps = parseGradle(
      '/p/build.gradle.kts',
      'dependencies {\n    implementation("com.squareup.okio:okio:3.6.0")\n    testImplementation(kotlin("test"))\n}',
    );
    expect(deps.map((d) => d.name)).toEqual(['com.squareup.okio:okio']);
  });
});

describe('sources jar extraction', () => {
  it('rejects entry names that escape the destination', () => {
    expect(safeEntryPath('/d', 'a/B.java')).toBe(path.resolve('/d/a/B.java'));
    expect(safeEntryPath('/d', '../x.java')).toBeUndefined();
    expect(safeEntryPath('/d', '/abs.java')).toBeUndefined();
    expect(safeEntryPath('/d', 'C:/x.java')).toBeUndefined();
  });

  it('extracts safe .java entries, skips hostile ones, and only once', async () => {
    const dest = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-jar-')), 'out');
    const jar = path.join(M2, 'com/evil/zipslip/1.0/zipslip-1.0-sources.jar');
    const first = await extractJar(jar, dest);
    expect(first.files.map((f) => path.relative(dest, f))).toEqual([path.join('ok', 'Fine.java')]);
    expect(first.skipped).toBe(2);
    expect(existsSync(path.join(dest, '..', '..', 'escape.java'))).toBe(false);
    expect((await extractJar(jar, dest)).files).toEqual([]);
  });

  it('enforces size limits and fails on non-archives', async () => {
    const dest = path.join(await mkdtemp(path.join(tmpdir(), 'depthreat-jar-')), 'out');
    const jar = path.join(M2, 'com/evil/telemetry/1.0.0/telemetry-1.0.0-sources.jar');
    const small = await extractJar(jar, dest, {
      include: (n) => n.endsWith('.java'),
      maxEntries: 10,
      maxEntryBytes: 10,
      maxTotalBytes: 1000,
    });
    expect(small).toEqual({ files: [], skipped: 1 });
    const bogus = path.join(path.dirname(dest), 'bogus.jar');
    await writeFile(bogus, 'not a zip');
    await expect(extractJar(bogus, path.join(dest, 'x'))).rejects.toThrow();
  });
});

describe('java resolve', () => {
  it('extracts sources from the Maven repository and walks dependency poms', async () => {
    const deps = byName(await resolve(path.join(SAMPLE, 'pom.xml')));
    const telemetry = deps.get('com.evil:telemetry')!;
    expect(telemetry).toMatchObject({ version: '1.0.0', direct: true });
    expect(existsSync(path.join(telemetry.installPath!, 'com/evil/Telemetry.java'))).toBe(true);
    expect(deps.get('org.clean:core')).toMatchObject({
      direct: false,
      version: '2.0.0',
      via: ['com.evil:telemetry'],
    });
    expect(deps.has('org.optional:extra')).toBe(false);
    expect(deps.get('com.missing:lib')).toMatchObject({ version: '3.1.0' });
    expect(deps.get('com.missing:lib')?.installPath).toBeUndefined();
    expect(deps.has('junit:junit')).toBe(false);
  });

  it('honors dev and transitive settings', async () => {
    const pom = path.join(SAMPLE, 'pom.xml');
    expect(byName(await resolve(pom, { includeDev: true })).get('junit:junit')?.isDev).toBe(true);
    expect(byName(await resolve(pom, { scanTransitive: false })).has('org.clean:core')).toBe(false);
  });

  it('finds sources jars in the Gradle cache', async () => {
    const deps = byName(await resolve(path.join(GRADLE, 'build.gradle')));
    expect(deps.get('com.evil:telemetry')?.installPath).toBeDefined();
    expect(deps.get('org.dynamic:lib')).toMatchObject({ version: 'unknown' });
  });

  it('stops when aborted', async () => {
    await expect(
      resolve(path.join(SAMPLE, 'pom.xml'), { signal: AbortSignal.abort() }),
    ).rejects.toThrow();
  });
});

describe('java files', () => {
  it('matches build files outside build output and caches', () => {
    expect(java.matches('/p/pom.xml')).toBe(true);
    expect(java.matches('/p/build.gradle.kts')).toBe(true);
    expect(java.matches('/p/target/classes/pom.xml')).toBe(false);
    expect(java.matches('/home/u/.m2/repository/x/pom.xml')).toBe(false);
    expect(java.matches('/p/settings.gradle')).toBe(false);
  });

  it('detects languages and lists extracted sources', async () => {
    expect(java.languageOf('/x/A.java')).toBe('java');
    expect(java.languageOf('/x/a.sh')).toBe('shell');
    expect(java.languageOf('/x/A.kt')).toBeUndefined();
    const dep = byName(await resolve(path.join(SAMPLE, 'pom.xml'))).get('org.clean:util')!;
    const files = await java.listSourceFiles(dep, DEFAULT_LIMITS);
    expect(files.map((f) => path.basename(f))).toEqual(['Util.java']);
    const missing = byName(await resolve(path.join(SAMPLE, 'pom.xml'))).get('com.missing:lib')!;
    expect(await java.listSourceFiles(missing, DEFAULT_LIMITS)).toEqual([]);
  });

  it('has sensible default locations', () => {
    const loc = defaultJavaLocations({ GRADLE_USER_HOME: '/g' });
    expect(loc.gradleCache).toBe(path.join('/g', 'caches', 'modules-2', 'files-2.1'));
    expect(loc.m2Repo).toMatch(/\.m2[\\/]repository$/);
  });
});

describe('java fixtures end to end', () => {
  const findings = new Map<string, Finding[]>();

  beforeAll(async () => {
    const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
      compileRule,
    );
    for (const dep of await resolve(path.join(SAMPLE, 'pom.xml'))) {
      const files = await java.listSourceFiles(dep, DEFAULT_LIMITS);
      findings.set(
        dep.name,
        await scanPackageCode({
          dep,
          files,
          languageOf: java.languageOf,
          rules,
          maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
        }),
      );
    }
  });

  const ids = (name: string) => (findings.get(name) ?? []).map((f) => f.ruleId).sort();

  it('flags environment exfiltration', () => {
    expect(ids('com.evil:telemetry')).toEqual([
      'env-access/java-getenv-all',
      'exfiltration/java-env-to-network',
    ]);
  });

  it('still scans the safe part of a hostile jar', () => {
    expect(ids('com.evil:zipslip')).toEqual(['exec/java-process', 'exec/java-shell']);
  });

  it('reports nothing for clean libraries', () => {
    expect(ids('org.clean:util')).toEqual([]);
    expect(ids('org.clean:core')).toEqual([]);
  });
});
