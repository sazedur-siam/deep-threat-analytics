import type { Policy } from '../config/projectConfig';
import { severityRank, type Finding, type PackageRef } from '../core/types';
import { matchesAny, matchesPackage } from './glob';

export interface PolicyViolation {
  policy: string;
  action: 'error' | 'warn';
  findingId: string;
  package: PackageRef;
  ruleId: string;
}

export type PolicyStatus = 'pass' | 'warn' | 'fail';

export interface PolicyResult {
  findings: Finding[];
  violations: PolicyViolation[];
  status: PolicyStatus;
}

function violates(f: Finding, p: Policy): boolean {
  if (p.packages && !p.packages.some((g) => matchesPackage(f.package, g))) return false;
  const { category, rule, source, minSeverity } = p.deny;
  if (category && !category.includes(f.category)) return false;
  if (rule && !matchesAny(f.ruleId, rule)) return false;
  if (source && !source.includes(f.source)) return false;
  if (minSeverity && severityRank(f.severity) < severityRank(minSeverity)) return false;
  return true;
}

/**
 * Check findings against policy gates. Every deny criterion given must match. Suppressed
 * findings never violate a policy. Any `error` violation fails; otherwise any `warn` warns.
 */
export function evaluatePolicies(
  findings: readonly Finding[],
  policies: readonly Policy[],
): PolicyResult {
  const violations: PolicyViolation[] = [];
  const out = findings.map((f) => {
    if (f.suppressed) return { ...f };
    const hit = policies.filter((p) => violates(f, p));
    if (!hit.length) return { ...f };
    for (const p of hit) {
      violations.push({
        policy: p.name,
        action: p.action,
        findingId: f.id,
        package: f.package,
        ruleId: f.ruleId,
      });
    }
    return { ...f, policyViolations: hit.map((p) => p.name) };
  });
  const status: PolicyStatus = violations.some((v) => v.action === 'error')
    ? 'fail'
    : violations.length
      ? 'warn'
      : 'pass';
  return { findings: out, violations, status };
}
