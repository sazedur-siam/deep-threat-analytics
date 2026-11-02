import * as path from 'node:path';
import type { Language } from '../core/types';
import type { EcosystemAdapter } from './adapter';
import { parsePackageJson } from './npm/manifest';
import { resolveNpm } from './npm/resolve';
import { walkFiles } from './walk';

const LANGUAGE_BY_EXT: Record<string, Language> = {
  '.js': 'javascript',
  '.cjs': 'javascript',
  '.mjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.sh': 'shell',
};

const SKIP_DIRS = new Set(['node_modules', '.git']);

function isTypeDeclaration(file: string): boolean {
  return /\.d\.[cm]?ts$/.test(file);
}

export const npmAdapter: EcosystemAdapter = {
  id: 'npm',
  osvEcosystem: 'npm',
  manifestGlobs: ['**/package.json'],

  matches(manifestPath) {
    const parts = manifestPath.split(/[\\/]/);
    return parts.at(-1) === 'package.json' && !parts.includes('node_modules');
  },

  parseManifest: parsePackageJson,

  resolve: resolveNpm,

  async listSourceFiles(dep, limits) {
    if (!dep.installPath) return [];
    return walkFiles(dep.installPath, {
      limits,
      skipDirs: SKIP_DIRS,
      include: (file) => npmAdapter.languageOf(file) !== undefined,
    });
  },

  languageOf(file) {
    if (path.basename(file) === 'package.json') return 'json';
    if (isTypeDeclaration(file)) return undefined;
    return LANGUAGE_BY_EXT[path.extname(file).toLowerCase()];
  },
};
