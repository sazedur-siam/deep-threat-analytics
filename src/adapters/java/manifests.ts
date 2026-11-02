import { LineIndex, splitLines } from '../../core/text';
import type { DeclaredDep } from '../../core/types';
import { parseIgnoreMarker } from '../ignore';

export interface PomDependency {
  groupId: string;
  artifactId: string;
  version?: string;
  scope?: string;
  optional: boolean;
  /** Offset of the artifactId text in the pom. */
  offset: number;
  block: string;
}

const tag = (xml: string, name: string) =>
  new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(xml)?.[1];

/** Replace `${prop}` placeholders; unresolved placeholders leave the value undefined. */
export function interpolate(
  value: string | undefined,
  props: Map<string, string>,
): string | undefined {
  if (value === undefined) return undefined;
  let out = value;
  for (let i = 0; i < 5 && out.includes('${'); i++) {
    out = out.replace(/\$\{([^}]+)\}/g, (m, key: string) => props.get(key) ?? m);
  }
  return out.includes('${') ? undefined : out;
}

/** Blank out a region while keeping offsets stable. */
const blank = (s: string, re: RegExp) => s.replace(re, (m) => ' '.repeat(m.length));

/** Properties usable in `${...}`: <properties>, project version/groupId, parent version. */
export function pomProperties(xml: string): Map<string, string> {
  const props = new Map<string, string>();
  const noComments = blank(xml, /<!--[\s\S]*?-->/g);
  const section = /<properties>([\s\S]*?)<\/properties>/.exec(noComments)?.[1] ?? '';
  for (const m of section.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g))
    props.set(m[1] as string, m[2] as string);
  const outside = blank(
    noComments,
    /<(parent|dependencies|dependencyManagement|build|profiles)>[\s\S]*?<\/\1>/g,
  );
  const parent = /<parent>([\s\S]*?)<\/parent>/.exec(noComments)?.[1] ?? '';
  const version = tag(outside, 'version') ?? tag(parent, 'version');
  const groupId = tag(outside, 'groupId') ?? tag(parent, 'groupId');
  if (version) props.set('project.version', version).set('version', version);
  if (groupId) props.set('project.groupId', groupId);
  const parentVersion = tag(parent, 'version');
  if (parentVersion) props.set('project.parent.version', parentVersion);
  return props;
}

/** <dependency> entries of a pom, outside dependencyManagement/plugins, versions interpolated. */
export function parsePomDependencies(xml: string): PomDependency[] {
  const props = pomProperties(xml);
  // Drop comments (they may contain example XML) but keep depthreat-ignore markers.
  let text = xml.replace(/<!--[\s\S]*?-->/g, (c) =>
    c.includes('depthreat-ignore') ? c : ' '.repeat(c.length),
  );
  // Managed versions apply to dependencies that omit <version>.
  const managed = new Map<string, string>();
  const mgmt = /<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/.exec(text)?.[1] ?? '';
  for (const m of mgmt.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = m[1] as string;
    const v = interpolate(tag(block, 'version'), props);
    if (v) managed.set(`${tag(block, 'groupId')}:${tag(block, 'artifactId')}`, v);
  }
  text = blank(text, /<(dependencyManagement|build|reporting)>[\s\S]*?<\/\1>/g);
  const out: PomDependency[] = [];
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = blank(m[1] as string, /<exclusions>[\s\S]*?<\/exclusions>/g);
    const groupId = interpolate(tag(block, 'groupId'), props);
    const artifactId = interpolate(tag(block, 'artifactId'), props);
    if (!groupId || !artifactId) continue;
    const artifactAt = block.search(/<artifactId>/);
    const valueStart =
      artifactAt + '<artifactId>'.length + (/<artifactId>(\s*)/.exec(block)?.[1]?.length ?? 0);
    out.push({
      groupId,
      artifactId,
      version: interpolate(tag(block, 'version'), props) ?? managed.get(`${groupId}:${artifactId}`),
      scope: tag(block, 'scope'),
      optional: tag(block, 'optional') === 'true',
      offset: (m.index as number) + '<dependency>'.length + valueStart,
      block: m[1] as string,
    });
  }
  return out;
}

export function parsePom(manifestPath: string, xml: string): DeclaredDep[] {
  const lines = new LineIndex(xml);
  return parsePomDependencies(xml).map((d) => {
    const ignoreComment = /<!--([^>]*depthreat-ignore[^>]*)-->/.exec(d.block)?.[1];
    const ignored = ignoreComment ? parseIgnoreMarker(ignoreComment) : undefined;
    return {
      ecosystem: 'maven',
      name: `${d.groupId}:${d.artifactId}`,
      versionSpec: d.version ?? '',
      manifestPath,
      range: lines.range(d.offset, d.offset + d.artifactId.length),
      isDev: d.scope === 'test',
      ...(ignored ? { ignoredRules: ignored } : {}),
    };
  });
}

const GRADLE_CONFIG =
  /^\s*(implementation|api|compile|compileOnly|runtimeOnly|runtime|kapt|annotationProcessor|testImplementation|testCompile|testCompileOnly|testRuntimeOnly|androidTestImplementation|debugImplementation|releaseImplementation)\b\s*\(?\s*(.*)$/;

/** build.gradle / build.gradle.kts dependency declarations (string and map notation). */
export function parseGradle(manifestPath: string, text: string): DeclaredDep[] {
  const out: DeclaredDep[] = [];
  splitLines(text).forEach((raw, line) => {
    const commentAt = raw.indexOf('//');
    const code = commentAt >= 0 ? raw.slice(0, commentAt) : raw;
    const comment = commentAt >= 0 ? raw.slice(commentAt + 2) : '';
    const m = GRADLE_CONFIG.exec(code);
    if (!m) return;
    const config = m[1] as string;
    const rest = m[2] as string;
    if (/^(platform|enforcedPlatform|project|files|fileTree)\s*\(/.test(rest)) return;
    let group: string | undefined;
    let name: string | undefined;
    let version: string | undefined;
    let col: number;
    let len: number;
    const coord = /["']([^"':\s]+):([^"':\s]+)(?::([^"'@\s]+))?(?:@\w+)?["']/.exec(rest);
    if (coord) {
      [group, name, version] = [coord[1], coord[2], coord[3]];
      col = raw.indexOf(coord[0]) + 1;
      len = (group as string).length + 1 + (name as string).length;
    } else {
      group = /group\s*[:=]\s*["']([^"']+)["']/.exec(rest)?.[1];
      name = /name\s*[:=]\s*["']([^"']+)["']/.exec(rest)?.[1];
      version = /version\s*[:=]\s*["']([^"']+)["']/.exec(rest)?.[1];
      if (!group || !name) return;
      col =
        raw.indexOf(`'${name}'`) >= 0 ? raw.indexOf(`'${name}'`) + 1 : raw.indexOf(`"${name}"`) + 1;
      len = name.length;
    }
    const ignored = parseIgnoreMarker(comment);
    out.push({
      ecosystem: 'maven',
      name: `${group}:${name}`,
      versionSpec: version && !version.includes('$') ? version : '',
      manifestPath,
      range: { startLine: line, startCol: col, endLine: line, endCol: col + len },
      isDev: /^(test|androidTest)/.test(config),
      ...(ignored ? { ignoredRules: ignored } : {}),
    });
  });
  return out;
}
