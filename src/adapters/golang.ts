import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import * as path from 'node:path';
import { splitLines } from '../core/text';
import type { DeclaredDep, Language, ResolvedDep } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { parseIgnoreMarker } from './ignore';
import { walkFiles } from './walk';

interface GoRequire {
  path: string;
  version: string;
  indirect: boolean;
  line: number;
  col: number;
  comment: string;
}

interface GoReplace {
  /** `module` or `module@version` on the left-hand side. */
  from: string;
  to: { path: string; version?: string };
}

/** Split `code // comment`. */
function splitComment(line: string): { code: string; comment: string } {
  const at = line.indexOf('//');
  return at < 0
    ? { code: line, comment: '' }
    : { code: line.slice(0, at), comment: line.slice(at + 2) };
}

/** Parse require and replace directives (single-line and block forms) from go.mod. */
export function parseGoModFile(text: string): { requires: GoRequire[]; replaces: GoReplace[] } {
  const requires: GoRequire[] = [];
  const replaces: GoReplace[] = [];
  let block: 'require' | 'replace' | undefined;
  splitLines(text).forEach((raw, line) => {
    const { code, comment } = splitComment(raw);
    const trimmed = code.trim();
    if (!trimmed) return;
    if (block && trimmed === ')') {
      block = undefined;
      return;
    }
    const open = /^(require|replace)\s*\($/.exec(trimmed);
    if (open) {
      block = open[1] as 'require' | 'replace';
      return;
    }
    let directive = block;
    let body = code;
    const single = /^(\s*)(require|replace)\s+/.exec(code);
    if (!block && single) {
      directive = single[2] as 'require' | 'replace';
      body = ' '.repeat(single[0].length) + code.slice(single[0].length);
    }
    if (directive === 'require') {
      const m = /^(\s*)(\S+)\s+(\S+)/.exec(body);
      if (m) {
        requires.push({
          path: m[2] as string,
          version: m[3] as string,
          indirect: /\bindirect\b/.test(comment),
          line,
          col: (m[1] as string).length,
          comment,
        });
      }
    } else if (directive === 'replace') {
      const m = /^\s*(\S+)(?:\s+(\S+))?\s*=>\s*(\S+)(?:\s+(\S+))?/.exec(body);
      if (m) {
        replaces.push({
          from: m[2] ? `${m[1]}@${m[2]}` : (m[1] as string),
          to: { path: m[3] as string, ...(m[4] ? { version: m[4] } : {}) },
        });
      }
    }
  });
  return { requires, replaces };
}

/** Module cache path escaping: upper-case letters become `!` + lower-case. */
export function escapeModulePath(p: string): string {
  return p.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

/** GOMODCACHE, else the first GOPATH entry's pkg/mod, else ~/go/pkg/mod. Never runs `go`. */
export function defaultModCache(env: NodeJS.ProcessEnv = process.env): string {
  if (env.GOMODCACHE) return env.GOMODCACHE;
  const gopath = env.GOPATH?.split(path.delimiter).find(Boolean);
  return path.join(gopath ?? path.join(homedir(), 'go'), 'pkg', 'mod');
}

const isLocalPath = (p: string) => p.startsWith('.') || path.isAbsolute(p);

export interface GoAdapterOptions {
  modCache?: string;
}

export function createGoAdapter(options: GoAdapterOptions = {}): EcosystemAdapter {
  const adapter: EcosystemAdapter = {
    id: 'go',
    osvEcosystem: 'Go',
    manifestGlobs: ['**/go.mod'],

    matches(manifestPath) {
      const parts = manifestPath.split(/[\\/]/);
      if (parts.at(-1) !== 'go.mod' || parts.includes('vendor') || parts.includes('testdata')) {
        return false;
      }
      return !/[\\/]pkg[\\/]mod[\\/]/.test(manifestPath);
    },

    parseManifest(manifestPath, text): DeclaredDep[] {
      return parseGoModFile(text).requires.map((r) => {
        const ignored = parseIgnoreMarker(r.comment);
        return {
          ecosystem: 'go',
          name: r.path,
          versionSpec: r.version,
          manifestPath,
          range: {
            startLine: r.line,
            startCol: r.col,
            endLine: r.line,
            endCol: r.col + r.path.length,
          },
          isDev: false,
          ...(ignored ? { ignoredRules: ignored } : {}),
        };
      });
    },

    async resolve(manifestPath, declared, ctx) {
      const { requires, replaces } = parseGoModFile(await readFile(manifestPath, 'utf8'));
      const indirect = new Set(requires.filter((r) => r.indirect).map((r) => r.path));
      const root = path.dirname(manifestPath);
      const vendor = existsSync(path.join(root, 'vendor', 'modules.txt'));
      const cache = options.modCache ?? defaultModCache();
      const out: ResolvedDep[] = [];
      for (const dep of declared) {
        ctx.signal?.throwIfAborted();
        const isIndirect = indirect.has(dep.name);
        if (isIndirect && !ctx.scanTransitive) continue;
        const replace =
          replaces.find((r) => r.from === `${dep.name}@${dep.versionSpec}`) ??
          replaces.find((r) => r.from === dep.name);
        // A local replacement is first-party code, not a dependency.
        if (replace && isLocalPath(replace.to.path)) continue;
        const target = replace
          ? { path: replace.to.path, version: replace.to.version ?? dep.versionSpec }
          : { path: dep.name, version: dep.versionSpec };
        const dir = vendor
          ? path.join(root, 'vendor', target.path)
          : path.join(
              cache,
              `${escapeModulePath(target.path)}@${escapeModulePath(target.version)}`,
            );
        out.push({
          ecosystem: 'go',
          name: target.path,
          version: target.version,
          ...(existsSync(dir) ? { installPath: dir } : {}),
          direct: !isIndirect,
          isDev: false,
          declared: dep,
        });
      }
      return out;
    },

    async listSourceFiles(dep, limits) {
      if (!dep.installPath) return [];
      return walkFiles(dep.installPath, {
        limits,
        skipDirs: new Set(['testdata', 'vendor', '.git']),
        include: (f) => adapter.languageOf(f) !== undefined,
      });
    },

    languageOf(file): Language | undefined {
      if (file.endsWith('_test.go')) return undefined;
      if (file.endsWith('.go')) return 'go';
      return file.endsWith('.sh') ? 'shell' : undefined;
    },
  };
  return adapter;
}

export const goAdapter = createGoAdapter();
