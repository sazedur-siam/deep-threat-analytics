// View models for the UI layer. No `vscode` import here, so this file is unit-tested directly.
import type { DiagnosticLevel } from '../config/settings';
import type { ScanResult } from '../core/engine';
import { packageKey } from '../core/findings';
import {
  maxSeverity,
  severityRank,
  type DeclaredDep,
  type Finding,
  type Severity,
} from '../core/types';

/** Findings the user should see: not suppressed and at/above minSeverity (violations always). */
export function visibleFindings(findings: readonly Finding[], minSeverity: Severity): Finding[] {
  const min = severityRank(minSeverity);
  return findings.filter(
    (f) =>
      !f.suppressed && (severityRank(f.severity) >= min || (f.policyViolations?.length ?? 0) > 0),
  );
}

function bySeverityDesc(a: Finding, b: Finding): number {
  return severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title);
}

/** One manifest line (a direct dependency) with every finding from it and its transitive deps. */
export interface DepAnchor {
  manifestPath: string;
  dep: DeclaredDep;
  findings: Finding[];
  severity: Severity;
  /** Policies violated by any of the findings, and whether any of them blocks (action: error). */
  policies: string[];
  blocking: boolean;
  /** Package name → chain of names from the direct dependency, for transitive packages. */
  via: Map<string, string[]>;
}

export function buildAnchors(result: ScanResult, minSeverity: Severity): DepAnchor[] {
  const visible = visibleFindings(result.findings, minSeverity);
  const byPackage = new Map<string, Finding[]>();
  for (const f of visible) {
    const key = packageKey(f.package);
    byPackage.set(key, [...(byPackage.get(key) ?? []), f]);
  }
  const blockingIds = new Set(
    result.violations.filter((v) => v.action === 'error').map((v) => v.findingId),
  );
  const anchors: DepAnchor[] = [];
  for (const m of result.manifests) {
    const groups = new Map<
      DeclaredDep,
      { findings: Map<string, Finding>; via: Map<string, string[]> }
    >();
    for (const dep of m.deps) {
      if (!dep.declared) continue;
      const found = byPackage.get(packageKey(dep));
      if (!found) continue;
      const group = groups.get(dep.declared) ?? { findings: new Map(), via: new Map() };
      for (const f of found) group.findings.set(f.id, f);
      if (dep.via) group.via.set(dep.name, dep.via);
      groups.set(dep.declared, group);
    }
    for (const [dep, group] of groups) {
      const findings = [...group.findings.values()].sort(bySeverityDesc);
      anchors.push({
        manifestPath: m.manifestPath,
        dep,
        findings,
        severity: maxSeverity(findings.map((f) => f.severity)) as Severity,
        policies: [...new Set(findings.flatMap((f) => f.policyViolations ?? []))],
        blocking: findings.some((f) => blockingIds.has(f.id)),
        via: group.via,
      });
    }
  }
  return anchors;
}

/** Diagnostic level for an anchor: blocking policy violations are always errors. */
export function anchorLevel(
  anchor: DepAnchor,
  mapping: Record<Severity, DiagnosticLevel>,
): DiagnosticLevel {
  if (anchor.blocking) return 'error';
  const mapped = mapping[anchor.severity];
  if (anchor.policies.length && (mapped === 'information' || mapped === 'hint')) return 'warning';
  return mapped;
}

export function anchorMessage(anchor: DepAnchor): string {
  const [top] = anchor.findings;
  if (!top) return '';
  const where =
    top.package.name === anchor.dep.name
      ? ''
      : ` (in ${top.package.name}, via ${[...(anchor.via.get(top.package.name) ?? [])].join(' → ')})`;
  const more = anchor.findings.length > 1 ? ` and ${anchor.findings.length - 1} more` : '';
  const policy = anchor.policies.length ? ` — violates policy: ${anchor.policies.join(', ')}` : '';
  return `[${top.severity}] ${top.title}${where}${more}${policy}`;
}

export type TreeNode =
  | { kind: 'violations'; label: string; children: TreeNode[] }
  | { kind: 'manifest'; label: string; manifestPath: string; children: TreeNode[] }
  | {
      kind: 'package';
      label: string;
      description: string;
      severity: Severity;
      packageKey: string;
      children: TreeNode[];
    }
  | { kind: 'finding'; label: string; description: string; finding: Finding; children: [] };

function findingNode(f: Finding): TreeNode {
  const policy = f.policyViolations?.length ? ` · policy: ${f.policyViolations.join(', ')}` : '';
  return {
    kind: 'finding',
    label: f.title,
    description: `${f.severity} · ${f.ruleId}${policy}`,
    finding: f,
    children: [],
  };
}

/**
 * Tree: optional "Policy violations" group, then Manifest › Package › Finding. Manifest labels
 * are made relative by `relative` (workspace-relative paths in the extension).
 */
export function buildTree(
  result: ScanResult,
  minSeverity: Severity,
  relative: (p: string) => string = (p) => p,
): TreeNode[] {
  const visible = visibleFindings(result.findings, minSeverity);
  const roots: TreeNode[] = [];
  const violating = visible.filter((f) => f.policyViolations?.length);
  if (violating.length) {
    roots.push({
      kind: 'violations',
      label: `Policy violations (${violating.length})`,
      children: violating.sort(bySeverityDesc).map(findingNode),
    });
  }
  const byPackage = new Map<string, Finding[]>();
  for (const f of visible) {
    const key = packageKey(f.package);
    byPackage.set(key, [...(byPackage.get(key) ?? []), f]);
  }
  for (const m of result.manifests) {
    const packages: TreeNode[] = [];
    const seen = new Set<string>();
    for (const dep of m.deps) {
      const key = packageKey(dep);
      const found = byPackage.get(key);
      if (!found || seen.has(key)) continue;
      seen.add(key);
      const sorted = [...found].sort(bySeverityDesc);
      const severity = sorted[0]!.severity;
      const via = dep.via?.length ? ` · via ${dep.via.join(' → ')}` : '';
      packages.push({
        kind: 'package',
        label: `${dep.name}@${dep.version}`,
        description: `${sorted.length} finding${sorted.length === 1 ? '' : 's'} · ${severity}${via}`,
        severity,
        packageKey: key,
        children: sorted.map(findingNode),
      });
    }
    if (!packages.length) continue;
    packages.sort(
      (a, b) =>
        severityRank((b as { severity: Severity }).severity) -
          severityRank((a as { severity: Severity }).severity) || a.label.localeCompare(b.label),
    );
    roots.push({
      kind: 'manifest',
      label: relative(m.manifestPath),
      manifestPath: m.manifestPath,
      children: packages,
    });
  }
  return roots;
}

export interface ScanSummary {
  text: string;
  status: ScanResult['status'];
  count: number;
  severity?: Severity;
}

export function summarizeScan(result: ScanResult, minSeverity: Severity): ScanSummary {
  const visible = visibleFindings(result.findings, minSeverity);
  const severity = maxSeverity(visible.map((f) => f.severity));
  const count = visible.length;
  const issues = count ? `${count} issue${count === 1 ? '' : 's'}` : 'no issues';
  const policy =
    result.status === 'fail'
      ? ' · policy failed'
      : result.status === 'warn'
        ? ' · policy warnings'
        : '';
  return {
    text: `${issues} in ${result.stats.packages} packages${policy}`,
    status: result.status,
    count,
    ...(severity ? { severity } : {}),
  };
}

/** Markdown hover body for a dependency anchor. */
export function anchorHover(anchor: DepAnchor, max = 8): string {
  const lines = [`**Deep Threat Analytics** — \`${anchor.dep.name}\``, ''];
  for (const f of anchor.findings.slice(0, max)) {
    const inPkg =
      f.package.name === anchor.dep.name ? '' : ` _(in ${f.package.name}@${f.package.version})_`;
    lines.push(`- **${f.severity}** ${f.title}${inPkg}  \n  ${f.message}`);
  }
  if (anchor.findings.length > max) lines.push(`- …and ${anchor.findings.length - max} more`);
  if (anchor.policies.length) lines.push('', `Violates policy: ${anchor.policies.join(', ')}`);
  return lines.join('\n');
}
