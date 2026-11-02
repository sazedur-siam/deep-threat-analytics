import { findNodeAtLocation, getNodeValue, parseTree, type Node } from 'jsonc-parser';
import { LineIndex } from '../../core/text';
import type { DeclaredDep } from '../../core/types';

const SECTIONS: ReadonlyArray<{ key: string; isDev: boolean }> = [
  { key: 'dependencies', isDev: false },
  { key: 'optionalDependencies', isDev: false },
  { key: 'peerDependencies', isDev: false },
  { key: 'devDependencies', isDev: true },
];

/** `"depthreat": { "ignore": { "<pkg>": ["rule/glob", ...] | "all" } }` */
function readInlineIgnores(root: Node): Map<string, string[] | 'all'> {
  const ignores = new Map<string, string[] | 'all'>();
  const node = findNodeAtLocation(root, ['depthreat', 'ignore']);
  if (!node || node.type !== 'object') return ignores;
  const value = getNodeValue(node) as Record<string, unknown>;
  for (const [name, entry] of Object.entries(value)) {
    if (entry === 'all') ignores.set(name, 'all');
    else if (Array.isArray(entry)) {
      const rules = entry.filter((r): r is string => typeof r === 'string' && r.length > 0);
      if (rules.length) ignores.set(name, rules);
    }
  }
  return ignores;
}

/**
 * Parse package.json into declared dependencies. Each `range` covers the dependency name
 * inside its quotes. Malformed JSON yields an empty list.
 */
export function parsePackageJson(manifestPath: string, text: string): DeclaredDep[] {
  const errors: { error: number }[] = [];
  const root = parseTree(text, errors, { allowTrailingComma: true });
  if (!root || root.type !== 'object' || errors.length) return [];
  const lines = new LineIndex(text);
  const ignores = readInlineIgnores(root);
  const deps: DeclaredDep[] = [];
  for (const { key, isDev } of SECTIONS) {
    const section = findNodeAtLocation(root, [key]);
    if (!section || section.type !== 'object') continue;
    for (const prop of section.children ?? []) {
      const [nameNode, valueNode] = prop.children ?? [];
      if (!nameNode || typeof nameNode.value !== 'string') continue;
      const name = nameNode.value;
      const versionSpec = typeof valueNode?.value === 'string' ? valueNode.value : '';
      const ignored = ignores.get(name);
      deps.push({
        ecosystem: 'npm',
        name,
        versionSpec,
        manifestPath,
        range: lines.range(nameNode.offset + 1, nameNode.offset + nameNode.length - 1),
        isDev,
        ...(ignored ? { ignoredRules: ignored } : {}),
      });
    }
  }
  return deps;
}
