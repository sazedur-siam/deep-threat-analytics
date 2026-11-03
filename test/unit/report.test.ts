import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { npmAdapter } from '../../src/adapters/npm';
import { parseProjectConfig } from '../../src/config/projectConfig';
import { DEFAULT_SETTINGS } from '../../src/config/settings';
import { scanManifests, type ScanResult } from '../../src/core/engine';
import type { Finding } from '../../src/core/types';
import { codeSpan, escapeMarkdown, renderMarkdownReport } from '../../src/report/markdown';
import { compileRule, loadRules } from '../../src/rules/loader';

const SAMPLE = path.resolve(__dirname, '../fixtures/npm-sample');
const NOW = new Date('2026-11-03T10:15:00Z');
let result: ScanResult;

beforeAll(async () => {
  const loaded = await loadRules([path.resolve(__dirname, '../../rules/builtin')]);
  result = await scanManifests([path.join(SAMPLE, 'package.json')], {
    adapters: [npmAdapter],
    rules: loaded.rules.map(compileRule),
    rulesHash: loaded.hash,
    settings: DEFAULT_SETTINGS,
    trusted: true,
    projectConfig: parseProjectConfig(`
ignore: [{ package: evil-env-stealer, rule: env-access/* }]
policies:
  - { name: no-install-hooks, deny: { category: install-hook } }
`).config,
  });
});

const render = (r: ScanResult = result, minSeverity: Finding['severity'] = 'low') =>
  renderMarkdownReport(r, {
    generatedAt: NOW,
    minSeverity,
    relative: (p) => path.relative(SAMPLE, p),
    extensionVersion: '0.2.0',
  });

describe('escaping', () => {
  it('neutralizes Markdown and HTML in untrusted text', () => {
    expect(escapeMarkdown('[x](http://evil) <img> a|b *c*\nnext')).toBe(
      '\\[x\\]\\(http://evil\\) \\<img\\> a\\|b \\*c\\* next',
    );
  });

  it('builds code spans that backticks cannot break', () => {
    expect(codeSpan('a.js:3')).toBe('`a.js:3`');
    expect(codeSpan('x = `y`')).toBe('`` x = `y` ``');
    const span = codeSpan('run(`id`)\n``x``');
    const fence = span.match(/^`+/)![0];
    expect(fence.length).toBe(3);
    expect(span.endsWith(fence)).toBe(true);
    expect(span).not.toContain('\n');
    expect(codeSpan('`start')).toBe('`` `start ``');
  });
});

describe('renderMarkdownReport', () => {
  it('summarizes the scan', () => {
    const md = render();
    expect(md).toMatch(/^# DepThreat Analytics report\n/);
    expect(md).toContain('Generated 2026-11-03T10:15:00.000Z by DepThreat Analytics 0.2.0.');
    expect(md).toContain('Policy status: **❌ failed**');
    expect(md).toMatch(/\| Suppressed by config or inline ignores \| 1 \|/);
    expect(md).toContain('| Policy violations | 1 |');
  });

  it('breaks issues down by severity, category and ecosystem', () => {
    const md = render();
    expect(md).toContain('### By severity');
    expect(md).toContain('| 🟠 high | 1 |');
    expect(md).toContain('| exec | 2 |');
    expect(md).toContain('| npm | 5 |');
  });

  it('lists policy violations and per-package findings with locations and evidence', () => {
    const md = render();
    expect(md).toContain(
      '| no-install-hooks | error | evil-postinstall@2.1.0 | `install-hook/npm-lifecycle-script` |',
    );
    expect(md).toContain('### evil-env-stealer@1.0.0 (npm)');
    expect(md).toContain('`node_modules/evil-env-stealer/index.js:5`');
    expect(md).toContain('  - Evidence: `const payload = JSON.stringify(process.env);`');
    expect(md).toContain('(policy: no-install-hooks)');
    // The worst package comes first.
    expect(md.indexOf('### evil-postinstall')).toBeLessThan(md.indexOf('### evil-env-stealer'));
  });

  it('reports suppressions, hidden findings and problems', () => {
    const md = render({ ...result, errors: ['OSV lookup failed: request timed out'] }, 'high');
    expect(md).toContain('## Suppressed findings');
    expect(md).toContain('| ignored in .depthreat/config.yaml | 1 |');
    expect(md).toMatch(/\| Below minimum severity \(high\) \| \d+ \|/);
    expect(md).toContain('## Problems during the scan');
    expect(md).toContain('- OSV lookup failed: request timed out');
  });

  it('handles a clean scan', () => {
    const clean: ScanResult = {
      ...result,
      findings: [],
      violations: [],
      status: 'pass',
      errors: [],
    };
    const md = render(clean);
    expect(md).toContain('**No issues** found in');
    expect(md).toContain('**✅ pass**');
    expect(md).not.toContain('## Findings by package');
    expect(md).not.toContain('### By severity');
  });

  it('keeps hostile package data from injecting Markdown', () => {
    const evil: Finding = {
      ...result.findings[0]!,
      id: 'ffffffffffffffff',
      suppressed: undefined,
      policyViolations: undefined,
      severity: 'critical',
      title: 'Test',
      message: 'pkg [click](https://evil.example.invalid) <script>',
      package: { ecosystem: 'npm', name: '[pwn](https://evil.example.invalid)', version: '1.0.0' },
      evidence: 'x`y',
      references: ['https://osv.dev/vulnerability/X-1', 'javascript:alert(1)'],
      fixedVersion: '1.0.1',
    };
    const md = render({ ...result, findings: [evil] });
    expect(md).toContain('### \\[pwn\\]\\(https://evil.example.invalid\\)@1.0.0 (npm)');
    expect(md).toContain('pkg \\[click\\]\\(https://evil.example.invalid\\) \\<script\\>');
    expect(md).toContain('Evidence: ``x`y``');
    expect(md).toContain('  - Fixed in `1.0.1`');
    expect(md).toContain('  - <https://osv.dev/vulnerability/X-1>');
    expect(md).not.toContain('javascript:');
    expect(md).toContain('**1 issue** found');
  });

  it('works without optional display settings', () => {
    const md = renderMarkdownReport(result, { generatedAt: NOW, minSeverity: 'info' });
    expect(md).toContain(`Generated ${NOW.toISOString()}.`);
    expect(md).toContain(path.join(SAMPLE, 'node_modules/evil-env-stealer/index.js'));
  });
});
