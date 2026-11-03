// Markdown report for a finished scan. No `vscode` import, so it is unit-tested directly.
import type { ScanResult } from '../core/engine';
import { packageKey } from '../core/findings';
import {
  CATEGORIES,
  maxSeverity,
  SEVERITIES,
  severityRank,
  type Finding,
  type Severity,
} from '../core/types';

export interface ReportOptions {
  generatedAt: Date;
  minSeverity: Severity;
  /** Workspace-relative display path for a file. */
  relative?: (file: string) => string;
  extensionVersion?: string;
}

/**
 * Package names, paths and evidence come from untrusted dependency code: escape everything that
 * could become a link, HTML, emphasis or a table break when the report is previewed.
 */
export function escapeMarkdown(text: string): string {
  return text.replace(/[\\`*_{}[\]()<>#+!|~]/g, '\\$&').replace(/\r?\n/g, ' ');
}

/** Inline code span that cannot be broken out of, whatever backticks the evidence contains. */
export function codeSpan(text: string): string {
  const flat = text.replace(/\r?\n/g, ' ');
  const longest = Math.max(0, ...(flat.match(/`+/g) ?? []).map((m) => m.length));
  const fence = '`'.repeat(longest + 1);
  const pad = flat.startsWith('`') || flat.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${flat}${pad}${fence}`;
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '🔴 critical',
  high: '🟠 high',
  medium: '🟡 medium',
  low: '🔵 low',
  info: '⚪ info',
};

const STATUS_LABEL: Record<ScanResult['status'], string> = {
  pass: '✅ pass',
  warn: '⚠️ warnings',
  fail: '❌ failed',
};

function table(head: string[], rows: string[][]): string[] {
  return [
    `| ${head.join(' | ')} |`,
    `| ${head.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.join(' | ')} |`),
  ];
}

function count<T extends string>(items: readonly T[]): Map<T, number> {
  const out = new Map<T, number>();
  for (const item of items) out.set(item, (out.get(item) ?? 0) + 1);
  return out;
}

function bySeverityDesc(a: Finding, b: Finding): number {
  return severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId);
}

function location(f: Finding, relative: (p: string) => string): string {
  if (!f.location) return '—';
  return codeSpan(`${relative(f.location.file)}:${f.location.range.startLine + 1}`);
}

/** Render a complete Markdown report for a scan result. */
export function renderMarkdownReport(result: ScanResult, opts: ReportOptions): string {
  const relative = opts.relative ?? ((p: string) => p);
  const min = severityRank(opts.minSeverity);
  const suppressed = result.findings.filter((f) => f.suppressed);
  const visible = result.findings
    .filter((f) => !f.suppressed && (severityRank(f.severity) >= min || f.policyViolations?.length))
    .sort(bySeverityDesc);
  const hidden = result.findings.length - suppressed.length - visible.length;
  const top = maxSeverity(visible.map((f) => f.severity));

  const lines: string[] = [
    '# DepThreat Analytics report',
    '',
    `Generated ${opts.generatedAt.toISOString()}${opts.extensionVersion ? ` by DepThreat Analytics ${opts.extensionVersion}` : ''}.`,
    '',
    visible.length
      ? `**${visible.length} issue${visible.length === 1 ? '' : 's'}** found in ${result.stats.packages} packages (highest severity: **${top}**). Policy status: **${STATUS_LABEL[result.status]}**.`
      : `**No issues** found in ${result.stats.packages} packages. Policy status: **${STATUS_LABEL[result.status]}**.`,
    '',
    '## Summary',
    '',
    ...table(
      ['Metric', 'Value'],
      [
        ['Manifests scanned', String(result.manifests.length)],
        ['Packages', String(result.stats.packages)],
        ['Packages read from disk', String(result.stats.scanned)],
        ['Packages from cache', String(result.stats.cached)],
        ['Issues shown', String(visible.length)],
        ['Suppressed by config or inline ignores', String(suppressed.length)],
        [`Below minimum severity (${opts.minSeverity})`, String(hidden)],
        ['Policy violations', String(result.violations.length)],
        ['Scan time', `${(result.stats.durationMs / 1000).toFixed(1)} s`],
      ],
    ),
    '',
  ];

  if (visible.length) {
    const sev = count(visible.map((f) => f.severity));
    lines.push(
      '### By severity',
      '',
      ...table(
        ['Severity', 'Issues'],
        [...SEVERITIES]
          .reverse()
          .filter((s) => sev.has(s))
          .map((s) => [SEVERITY_LABEL[s], String(sev.get(s))]),
      ),
      '',
    );
    const cat = count(visible.map((f) => f.category));
    lines.push(
      '### By category',
      '',
      ...table(
        ['Category', 'Issues'],
        CATEGORIES.filter((c) => cat.has(c))
          .sort((a, b) => (cat.get(b) ?? 0) - (cat.get(a) ?? 0) || a.localeCompare(b))
          .map((c) => [c, String(cat.get(c))]),
      ),
      '',
    );
    const eco = count(visible.map((f) => f.package.ecosystem));
    lines.push(
      '### By ecosystem',
      '',
      ...table(
        ['Ecosystem', 'Issues'],
        [...eco.entries()].sort((a, b) => b[1] - a[1]).map(([e, n]) => [e, String(n)]),
      ),
      '',
    );
  }

  if (result.violations.length) {
    lines.push(
      '## Policy violations',
      '',
      ...table(
        ['Policy', 'Action', 'Package', 'Rule'],
        result.violations.map((v) => [
          escapeMarkdown(v.policy),
          v.action,
          escapeMarkdown(`${v.package.name}@${v.package.version}`),
          codeSpan(v.ruleId),
        ]),
      ),
      '',
    );
  }

  if (visible.length) {
    lines.push('## Findings by package', '');
    const groups = new Map<string, Finding[]>();
    for (const f of visible)
      groups.set(packageKey(f.package), [...(groups.get(packageKey(f.package)) ?? []), f]);
    const via = new Map<string, string[]>();
    for (const m of result.manifests) {
      for (const d of m.deps) if (d.via?.length) via.set(packageKey(d), d.via);
    }
    const ordered = [...groups.values()].sort(
      (a, b) => severityRank(b[0]!.severity) - severityRank(a[0]!.severity) || b.length - a.length,
    );
    for (const findings of ordered) {
      const pkg = findings[0]!.package;
      const chain = via.get(packageKey(pkg));
      lines.push(
        `### ${escapeMarkdown(`${pkg.name}@${pkg.version}`)} (${pkg.ecosystem})`,
        '',
        `${findings.length} issue${findings.length === 1 ? '' : 's'}, highest ${SEVERITY_LABEL[findings[0]!.severity]}${chain ? `. Pulled in via ${escapeMarkdown(chain.join(' → '))}` : ''}.`,
        '',
        ...table(
          ['Severity', 'Finding', 'Rule', 'Location'],
          findings.map((f) => [
            SEVERITY_LABEL[f.severity],
            escapeMarkdown(f.title) +
              (f.policyViolations?.length
                ? ` (policy: ${escapeMarkdown(f.policyViolations.join(', '))})`
                : ''),
            codeSpan(f.ruleId),
            location(f, relative),
          ]),
        ),
        '',
      );
      for (const f of findings) {
        const details = [`- **${escapeMarkdown(f.title)}**: ${escapeMarkdown(f.message)}`];
        if (f.evidence) details.push(`  - Evidence: ${codeSpan(f.evidence)}`);
        if (f.fixedVersion) details.push(`  - Fixed in ${codeSpan(f.fixedVersion)}`);
        for (const ref of (f.references ?? [])
          .filter((r) => /^https:\/\/[^\s<>()]+$/.test(r))
          .slice(0, 3)) {
          details.push(`  - <${ref}>`);
        }
        lines.push(...details);
      }
      lines.push('');
    }
  }

  if (suppressed.length) {
    const reasons = count(suppressed.map((f) => f.suppressed!.reason));
    lines.push(
      '## Suppressed findings',
      '',
      ...table(
        ['Reason', 'Findings'],
        [...reasons.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([r, n]) => [escapeMarkdown(r), String(n)]),
      ),
      '',
    );
  }

  if (result.errors.length) {
    lines.push(
      '## Problems during the scan',
      '',
      ...result.errors.map((e) => `- ${escapeMarkdown(e)}`),
      '',
    );
  }

  lines.push(
    '---',
    '',
    '_Code analysis ran locally; dependency code was read, never executed. Findings are pattern-based and can include false positives: review each one before acting on it._',
    '',
  );
  return lines.join('\n');
}
