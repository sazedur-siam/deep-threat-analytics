import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import * as path from 'node:path';
import type { Language, ResolvedDep } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { extractJar } from './java/jar';
import { parseGradle, parsePom, parsePomDependencies } from './java/manifests';
import { walkFiles } from './walk';

const MANIFESTS = new Set(['pom.xml', 'build.gradle', 'build.gradle.kts']);
const IGNORED_DIRS = ['target', 'build', '.m2', '.gradle', 'node_modules'];
/** Upper bound on artifacts visited through transitive poms. */
export const MAX_ARTIFACTS = 500;

export interface JavaAdapterOptions {
  /** Maven local repository (default ~/.m2/repository). */
  m2Repo?: string;
  /** Gradle module cache (default $GRADLE_USER_HOME/caches/modules-2/files-2.1). */
  gradleCache?: string;
  /** Where sources jars are unpacked for scanning (default: OS temp dir). */
  extractRoot?: string;
}

export function defaultJavaLocations(env: NodeJS.ProcessEnv = process.env) {
  const gradleHome = env.GRADLE_USER_HOME ?? path.join(homedir(), '.gradle');
  return {
    m2Repo: path.join(homedir(), '.m2', 'repository'),
    gradleCache: path.join(gradleHome, 'caches', 'modules-2', 'files-2.1'),
    extractRoot: path.join(tmpdir(), 'depthreat-java-sources'),
  };
}

const isConcrete = (v: string | undefined): v is string => !!v && /^\d[\w.+-]*$/.test(v);

export function createJavaAdapter(options: JavaAdapterOptions = {}): EcosystemAdapter {
  const loc = { ...defaultJavaLocations(), ...options };

  /** Find `<artifact>-<version><suffix>` in the Maven repository or the Gradle cache. */
  async function findArtifact(group: string, artifact: string, version: string, suffix: string) {
    const file = `${artifact}-${version}${suffix}`;
    const m2 = path.join(loc.m2Repo, ...group.split('.'), artifact, version, file);
    if (existsSync(m2)) return m2;
    const gradleDir = path.join(loc.gradleCache, group, artifact, version);
    try {
      for (const hash of (await readdir(gradleDir)).sort()) {
        const candidate = path.join(gradleDir, hash, file);
        if (existsSync(candidate)) return candidate;
      }
    } catch {
      // not in the Gradle cache
    }
    return undefined;
  }

  async function sourcesDir(group: string, artifact: string, version: string) {
    const jar = await findArtifact(group, artifact, version, '-sources.jar');
    if (!jar) return undefined;
    const dest = path.join(loc.extractRoot, group, `${artifact}-${version}`);
    try {
      await extractJar(jar, dest);
      return dest;
    } catch {
      return undefined;
    }
  }

  /** Compile/runtime dependencies declared in an artifact's own pom. */
  async function pomDependencies(group: string, artifact: string, version: string) {
    const pom = await findArtifact(group, artifact, version, '.pom');
    if (!pom) return [];
    try {
      return parsePomDependencies(await readFile(pom, 'utf8')).filter(
        (d) =>
          !d.optional &&
          (!d.scope || d.scope === 'compile' || d.scope === 'runtime') &&
          isConcrete(d.version),
      );
    } catch {
      return [];
    }
  }

  const adapter: EcosystemAdapter = {
    id: 'maven',
    osvEcosystem: 'Maven',
    manifestGlobs: ['**/pom.xml', '**/build.gradle', '**/build.gradle.kts'],

    matches(manifestPath) {
      const parts = manifestPath.split(/[\\/]/);
      return MANIFESTS.has(parts.at(-1) ?? '') && !parts.some((p) => IGNORED_DIRS.includes(p));
    },

    parseManifest(manifestPath, text) {
      return path.basename(manifestPath) === 'pom.xml'
        ? parsePom(manifestPath, text)
        : parseGradle(manifestPath, text);
    },

    async resolve(_manifestPath, declared, ctx) {
      const out: ResolvedDep[] = [];
      const seen = new Set<string>();
      const wanted = declared.filter((d) => ctx.includeDev || !d.isDev);
      const ordered = [...wanted.filter((d) => !d.isDev), ...wanted.filter((d) => d.isDev)];
      for (const root of ordered) {
        ctx.signal?.throwIfAborted();
        const [group, artifact] = root.name.split(':') as [string, string];
        const version = isConcrete(root.versionSpec) ? root.versionSpec : 'unknown';
        const key = `${root.name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const dir = version === 'unknown' ? undefined : await sourcesDir(group, artifact, version);
        out.push({
          ecosystem: 'maven',
          name: root.name,
          version,
          ...(dir ? { installPath: dir } : {}),
          direct: true,
          isDev: root.isDev,
          declared: root,
        });
        if (!ctx.scanTransitive || version === 'unknown') continue;
        const queue = [{ group, artifact, version, via: [root.name] }];
        while (queue.length && seen.size < MAX_ARTIFACTS) {
          ctx.signal?.throwIfAborted();
          const node = queue.shift()!;
          for (const child of await pomDependencies(node.group, node.artifact, node.version)) {
            const name = `${child.groupId}:${child.artifactId}`;
            const childKey = `${name}@${child.version}`;
            if (seen.has(childKey)) continue;
            seen.add(childKey);
            const childDir = await sourcesDir(
              child.groupId,
              child.artifactId,
              child.version as string,
            );
            out.push({
              ecosystem: 'maven',
              name,
              version: child.version as string,
              ...(childDir ? { installPath: childDir } : {}),
              direct: false,
              isDev: root.isDev,
              declared: root,
              via: node.via,
            });
            queue.push({
              group: child.groupId,
              artifact: child.artifactId,
              version: child.version as string,
              via: [...node.via, name],
            });
          }
        }
      }
      return out;
    },

    async listSourceFiles(dep, limits) {
      if (!dep.installPath) return [];
      return walkFiles(dep.installPath, {
        limits,
        skipDirs: new Set(),
        include: (f) => adapter.languageOf(f) !== undefined,
      });
    },

    languageOf(file): Language | undefined {
      if (file.endsWith('.java')) return 'java';
      return file.endsWith('.sh') ? 'shell' : undefined;
    },
  };
  return adapter;
}

export const javaAdapter = createJavaAdapter();
