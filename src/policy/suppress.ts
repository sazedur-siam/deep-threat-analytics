import type { ProjectConfig } from '../config/projectConfig';
import type { Finding } from '../core/types';
import { matchesAny, matchesGlob, matchesPackage, matchesVersion } from './glob';

/** Inline manifest ignores keyed by `ecosystem:name` (from DeclaredDep.ignoredRules). */
export type InlineIgnores = Map<string, string[] | 'all'>;

function suppressionReason(
  f: Finding,
  config: ProjectConfig,
  inline: InlineIgnores,
): string | undefined {
  if (config.allowlist.packages.some((p) => matchesPackage(f.package, p))) {
    return 'allowlisted package';
  }
  if (matchesAny(f.ruleId, config.allowlist.rules)) return 'allowlisted rule';
  for (const entry of config.ignore) {
    if ('finding' in entry) {
      if (entry.finding === f.id) return entry.reason ?? 'ignored finding';
      continue;
    }
    if (
      matchesPackage(f.package, entry.package) &&
      (entry.rule === undefined || matchesGlob(f.ruleId, entry.rule)) &&
      matchesVersion(f.package.version, entry.version)
    ) {
      return entry.reason ?? 'ignored in .depthreat/config.yaml';
    }
  }
  const marker = inline.get(`${f.package.ecosystem}:${f.package.name}`);
  if (marker === 'all' || (marker && matchesAny(f.ruleId, marker))) return 'ignored in manifest';
  return undefined;
}

/**
 * Apply severity overrides, then mark findings matched by allowlists or ignores as suppressed.
 * Suppressed findings are kept (so the UI can show them on request) and inputs are not mutated.
 */
export function applySuppressions(
  findings: readonly Finding[],
  config: ProjectConfig,
  inline: InlineIgnores = new Map(),
): Finding[] {
  return findings.map((f) => {
    const override = config.severityOverrides.find(
      (o) => matchesGlob(f.ruleId, o.rule) && (!o.package || matchesPackage(f.package, o.package)),
    );
    const next: Finding = override ? { ...f, severity: override.severity } : { ...f };
    const reason = suppressionReason(next, config, inline);
    if (reason) next.suppressed = { reason };
    return next;
  });
}
