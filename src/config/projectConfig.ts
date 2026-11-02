import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { isMap, isScalar, isSeq, parseDocument, type Document } from 'yaml';
import { z } from 'zod';
import { CATEGORIES, SEVERITIES } from '../core/types';

export const CONFIG_DIR = '.depthreat';
export const CONFIG_FILES = ['config.yaml', 'config.yml'];

const list = <T extends z.ZodTypeAny>(item: T) =>
  z
    .union([item, z.array(item).min(1)])
    .transform((v) => (Array.isArray(v) ? v : [v]) as z.output<T>[]);

const findingId = z.string().regex(/^[0-9a-f]{16}$/, 'finding ids are 16 hex characters');

export const ignoreSchema = z.union([
  z.strictObject({ finding: findingId, reason: z.string().optional() }),
  z.strictObject({
    package: z.string().min(1),
    /** Rule id or glob; omitted = every rule for the package. */
    rule: z.string().min(1).optional(),
    /** Version glob or x-range (`4.x`). */
    version: z.string().min(1).optional(),
    reason: z.string().optional(),
  }),
]);

export const severityOverrideSchema = z.strictObject({
  rule: z.string().min(1),
  package: z.string().min(1).optional(),
  severity: z.enum(SEVERITIES),
});

export const policySchema = z.strictObject({
  name: z.string().min(1),
  /** Package globs the policy is limited to; omitted = all packages. */
  packages: z.array(z.string().min(1)).optional(),
  deny: z
    .strictObject({
      category: list(z.enum(CATEGORIES)).optional(),
      rule: list(z.string().min(1)).optional(),
      source: list(z.enum(['code', 'install-hook', 'osv', 'reputation'])).optional(),
      minSeverity: z.enum(SEVERITIES).optional(),
    })
    .refine((d) => Object.values(d).some((v) => v !== undefined), {
      message: 'deny needs at least one of category, rule, source, minSeverity',
    }),
  action: z.enum(['error', 'warn']).default('error'),
});

const allowlistSchema = z.strictObject({
  packages: z.array(z.string().min(1)).default([]),
  rules: z.array(z.string().min(1)).default([]),
});

export type IgnoreEntry = z.output<typeof ignoreSchema>;
export type SeverityOverride = z.output<typeof severityOverrideSchema>;
export type Policy = z.output<typeof policySchema>;

export interface ProjectConfig {
  allowlist: { packages: string[]; rules: string[] };
  ignore: IgnoreEntry[];
  severityOverrides: SeverityOverride[];
  policies: Policy[];
}

export interface ConfigError {
  /** Dotted path such as `ignore[2].package`, or '' for file-level problems. */
  path: string;
  message: string;
}

export const EMPTY_CONFIG: ProjectConfig = Object.freeze({
  allowlist: Object.freeze({ packages: [], rules: [] }),
  ignore: [],
  severityOverrides: [],
  policies: [],
}) as ProjectConfig;

function issuesToErrors(prefix: string, error: z.ZodError): ConfigError[] {
  return error.issues.map((i) => ({
    path: [prefix, ...i.path.map((p) => (typeof p === 'number' ? `[${p}]` : `.${String(p)}`))]
      .join('')
      .replace(/^\./, ''),
    message: i.message,
  }));
}

/** Validate each entry of a list section on its own so one bad entry doesn't drop the rest. */
function parseList<T extends z.ZodTypeAny>(
  key: string,
  value: unknown,
  schema: T,
  errors: ConfigError[],
): z.output<T>[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    errors.push({ path: key, message: 'expected a list' });
    return [];
  }
  const out: z.output<T>[] = [];
  value.forEach((entry, i) => {
    const parsed = schema.safeParse(entry);
    if (parsed.success) out.push(parsed.data);
    else errors.push(...issuesToErrors(`${key}[${i}]`, parsed.error));
  });
  return out;
}

const SECTIONS = new Set(['allowlist', 'ignore', 'severityOverrides', 'policies']);

/** Parse config text. Never throws: problems are returned with paths, valid parts are kept. */
export function parseProjectConfig(text: string): { config: ProjectConfig; errors: ConfigError[] } {
  const doc = parseDocument(text);
  const errors: ConfigError[] = doc.errors.map((e) => ({ path: '', message: e.message }));
  if (errors.length) return { config: EMPTY_CONFIG, errors };
  const raw = doc.toJS() as unknown;
  if (raw === null || raw === undefined) return { config: EMPTY_CONFIG, errors };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      config: EMPTY_CONFIG,
      errors: [{ path: '', message: 'expected a mapping at the top level' }],
    };
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!SECTIONS.has(key)) errors.push({ path: key, message: `unknown section "${key}"` });
  }
  let allowlist = { packages: [] as string[], rules: [] as string[] };
  if (obj.allowlist !== undefined && obj.allowlist !== null) {
    const parsed = allowlistSchema.safeParse(obj.allowlist);
    if (parsed.success) allowlist = parsed.data;
    else errors.push(...issuesToErrors('allowlist', parsed.error));
  }
  return {
    config: {
      allowlist,
      ignore: parseList('ignore', obj.ignore, ignoreSchema, errors),
      severityOverrides: parseList(
        'severityOverrides',
        obj.severityOverrides,
        severityOverrideSchema,
        errors,
      ),
      policies: parseList('policies', obj.policies, policySchema, errors),
    },
    errors,
  };
}

/** Load `<folder>/.depthreat/config.yaml`. A missing file is an empty config, not an error. */
export async function loadProjectConfig(
  folder: string,
): Promise<{ config: ProjectConfig; errors: ConfigError[]; path?: string }> {
  for (const name of CONFIG_FILES) {
    const file = path.join(folder, CONFIG_DIR, name);
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    return { ...parseProjectConfig(text), path: file };
  }
  return { config: EMPTY_CONFIG, errors: [] };
}

function openDoc(text: string): Document {
  const doc = parseDocument(text);
  if (!isMap(doc.contents)) doc.contents = doc.createNode({}) as never;
  return doc;
}

/** Append `value` to the list at `keys`, creating it if needed; no-op when already present. */
function appendUnique(text: string, keys: string[], value: unknown): string {
  const doc = openDoc(text);
  let seq = doc.getIn(keys, true);
  // Only create the list when it is missing or empty; never overwrite other user content.
  const missing = seq === undefined || seq === null || (isScalar(seq) && seq.value === null);
  if (missing) {
    doc.setIn(keys, doc.createNode([]));
    seq = doc.getIn(keys, true);
  }
  if (!isSeq(seq)) return text;
  const wanted = JSON.stringify(value);
  if (seq.items.some((item) => JSON.stringify(doc.createNode(item).toJSON()) === wanted))
    return text;
  const node = doc.createNode(value);
  if (typeof value === 'object') (node as { flow?: boolean }).flow = true;
  seq.add(node);
  return doc.toString();
}

/** Comment-preserving edits used by Quick Fixes. Each returns the new file text. */
export function addIgnore(text: string, entry: IgnoreEntry): string {
  return appendUnique(text, ['ignore'], entry);
}

export function addAllowlistedPackage(text: string, pattern: string): string {
  return appendUnique(text, ['allowlist', 'packages'], pattern);
}

export function addAllowlistedRule(text: string, ruleId: string): string {
  return appendUnique(text, ['allowlist', 'rules'], ruleId);
}

export function defaultConfigTemplate(): string {
  return `# Deep Threat Analytics project configuration.
# Commit this file to share allowlists, ignores and policies with your team.

# Packages or rules that are trusted everywhere (globs; prefix packages with "npm:" or "pypi:").
allowlist:
  packages: []
  rules: []

# Suppress specific findings. Use "finding: <id>" for a single finding, or package/rule/version.
ignore: []
#  - { package: lodash, rule: obfuscation/*, reason: minified dist }

# Change the severity of a rule (optionally only for some packages).
severityOverrides: []
#  - { rule: network/*, severity: low }

# Policy gates: matching findings become errors (action: error) or warnings (action: warn).
policies:
  - { name: no-critical, deny: { minSeverity: critical }, action: error }
#  - { name: no-install-hooks, deny: { category: install-hook }, action: error }
#  - { name: no-network-in-crypto, packages: ['*crypto*'], deny: { category: [network, exfiltration] } }
`;
}
