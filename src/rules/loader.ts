import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { z } from 'zod';
import { ruleSchema, type Rule, type RulePattern } from './schema';

export interface RuleLoadError {
  file: string;
  /** Index of the rule within the file, when the error is rule-specific. */
  index?: number;
  message: string;
}

export interface LoadedRules {
  rules: Rule[];
  errors: RuleLoadError[];
  /** Changes whenever the effective rule set changes; part of the scan cache key. */
  hash: string;
}

export interface CompiledRule {
  rule: Rule;
  all: RegExp[];
  any: RegExp[];
  not: RegExp[];
}

function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((i) => `${i.path.length ? `${i.path.join('.')}: ` : ''}${i.message}`)
    .join('; ');
}

async function listRuleFiles(dir: string): Promise<string[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return [];
  }
  return entries
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort()
    .map((f) => path.join(dir, f));
}

/** Parse and validate one rule file. Invalid rules are reported and skipped; valid ones kept. */
export function parseRuleFile(file: string, text: string): { rules: Rule[]; errors: RuleLoadError[] } {
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch (e) {
    return { rules: [], errors: [{ file, message: `YAML parse error: ${(e as Error).message}` }] };
  }
  if (doc === null || doc === undefined) return { rules: [], errors: [] };
  if (!Array.isArray(doc)) {
    return { rules: [], errors: [{ file, message: 'rule file must contain a YAML list of rules' }] };
  }
  const rules: Rule[] = [];
  const errors: RuleLoadError[] = [];
  doc.forEach((raw, index) => {
    const parsed = ruleSchema.safeParse(raw);
    if (parsed.success) rules.push(parsed.data);
    else errors.push({ file, index, message: formatIssues(parsed.error) });
  });
  return { rules, errors };
}

/**
 * Load built-in rules, then user rule directories in order. A later rule with the same id
 * replaces an earlier one, so users can override or disable (enabled: false) built-ins.
 */
export async function loadRules(dirs: readonly string[]): Promise<LoadedRules> {
  const byId = new Map<string, Rule>();
  const errors: RuleLoadError[] = [];
  for (const dir of dirs) {
    for (const file of await listRuleFiles(dir)) {
      const result = parseRuleFile(file, await readFile(file, 'utf8'));
      errors.push(...result.errors);
      for (const rule of result.rules) byId.set(rule.id, rule);
    }
  }
  const rules = [...byId.values()].filter((r) => r.enabled);
  return { rules, errors, hash: hashRules(rules) };
}

export function hashRules(rules: readonly Rule[]): string {
  const canonical = JSON.stringify([...rules].sort((a, b) => a.id.localeCompare(b.id)));
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

function toRegExp(p: RulePattern): RegExp {
  return new RegExp(p.regex, `${p.flags ?? ''}gm`);
}

export function compileRule(rule: Rule): CompiledRule {
  return {
    rule,
    all: (rule.match.all ?? []).map(toRegExp),
    any: (rule.match.any ?? []).map(toRegExp),
    not: (rule.match.not ?? []).map(toRegExp),
  };
}
