import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { npmAdapter } from '../../src/adapters/npm';
import { parseProjectConfig } from '../../src/config/projectConfig';
import { DEFAULT_SETTINGS } from '../../src/config/settings';
import { scanManifests, type ScanResult } from '../../src/core/engine';
import { compileRule, loadRules } from '../../src/rules/loader';
import {
  anchorHover,
  anchorLevel,
  anchorMessage,
  buildAnchors,
  buildTree,
  fixedVersionEdit,
  summarizeScan,
  visibleFindings,
} from '../../src/ui/model';

const NPM = path.resolve(__dirname, '../fixtures/npm-sample/package.json');
let result: ScanResult;
let withPolicy: ScanResult;

beforeAll(async () => {
  const loaded = await loadRules([path.resolve(__dirname, '../../rules/builtin')]);
  const base = {
    adapters: [npmAdapter],
    rules: loaded.rules.map(compileRule),
    rulesHash: loaded.hash,
    settings: DEFAULT_SETTINGS,
    trusted: true,
  };
  result = await scanManifests([NPM], {
    ...base,
    projectConfig: parseProjectConfig('').config,
  });
  withPolicy = await scanManifests([NPM], {
    ...base,
    projectConfig: parseProjectConfig(`
ignore: [{ package: evil-env-stealer, rule: env-access/* }]
policies:
  - { name: no-install-hooks, deny: { category: install-hook } }
  - { name: watch-exec, deny: { rule: exec/node-child-process }, action: warn }
`).config,
  });
});

describe('visibleFindings', () => {
  it('drops suppressed findings and those below the minimum severity', () => {
    const all = visibleFindings(withPolicy.findings, 'info');
    expect(all.some((f) => f.ruleId.startsWith('env-access/'))).toBe(false);
    const high = visibleFindings(result.findings, 'high');
    expect(high.every((f) => f.severity === 'high' || f.severity === 'critical')).toBe(true);
  });

  it('always keeps policy violations', () => {
    const critical = visibleFindings(withPolicy.findings, 'critical');
    expect(critical.map((f) => f.ruleId).sort()).toEqual([
      'dynamic-code/download-and-execute',
      'exec/node-child-process',
      'install-hook/npm-lifecycle-script',
    ]);
  });
});

describe('anchors', () => {
  it('anchors findings on the direct dependency line', () => {
    const anchors = buildAnchors(result, 'low');
    expect(anchors.map((a) => a.dep.name).sort()).toEqual(['evil-env-stealer', 'evil-postinstall']);
    const stealer = anchors.find((a) => a.dep.name === 'evil-env-stealer')!;
    expect(stealer.severity).toBe('high');
    expect(stealer.findings[0]?.ruleId).toBe('exfiltration/env-to-network');
    expect(stealer.blocking).toBe(false);
    expect(anchorMessage(stealer)).toBe(
      '[high] Sends environment variables over the network and 1 more',
    );
    expect(anchorLevel(stealer, DEFAULT_SETTINGS.severityMapping)).toBe('error');
  });

  it('marks blocking and warning policy violations', () => {
    const anchors = buildAnchors(withPolicy, 'low');
    const hook = anchors.find((a) => a.dep.name === 'evil-postinstall')!;
    expect(hook.policies.sort()).toEqual(['no-install-hooks', 'watch-exec']);
    expect(hook.blocking).toBe(true);
    expect(anchorLevel(hook, { ...DEFAULT_SETTINGS.severityMapping, medium: 'hint' })).toBe(
      'error',
    );
    expect(anchorMessage(hook)).toContain('violates policy: ');
    const warnOnly = { ...hook, blocking: false };
    const allHint = {
      critical: 'hint',
      high: 'hint',
      medium: 'hint',
      low: 'hint',
      info: 'hint',
    } as const;
    expect(anchorLevel(warnOnly, allHint)).toBe('warning');
  });

  it('describes transitive findings with their path', () => {
    const [anchor] = buildAnchors(result, 'low');
    const transitive = {
      ...anchor!,
      dep: { ...anchor!.dep, name: 'parent' },
      via: new Map([[anchor!.findings[0]!.package.name, ['parent', 'middle']]]),
    };
    expect(anchorMessage(transitive)).toMatch(/\(in .+, via parent → middle\)/);
    expect(anchorMessage({ ...transitive, findings: [] })).toBe('');
  });

  it('renders hover markdown', () => {
    const anchors = buildAnchors(withPolicy, 'low');
    const hook = anchors.find((a) => a.dep.name === 'evil-postinstall')!;
    const md = anchorHover(hook, 1);
    expect(md).toContain('`evil-postinstall`');
    expect(md).toContain('…and 3 more');
    expect(md).toContain('Violates policy');
  });
});

describe('tree', () => {
  it('groups violations, manifests, packages and findings', () => {
    const tree = buildTree(withPolicy, 'low', (p) => path.basename(path.dirname(p)));
    expect(tree.map((n) => n.kind)).toEqual(['violations', 'manifest']);
    expect(tree[0]?.label).toBe('Policy violations (2)');
    const manifest = tree[1]!;
    expect(manifest.label).toBe('npm-sample');
    const packages = manifest.children;
    // The worst package comes first: evil-postinstall pipes a download into a shell (critical).
    expect(packages.map((p) => p.label)).toEqual([
      'evil-postinstall@2.1.0',
      'evil-env-stealer@1.0.0',
    ]);
    expect(packages[0]?.kind === 'package' && packages[0].description).toBe(
      '4 findings · critical',
    );
    const finding = packages[0]!.children.find(
      (c) => c.kind === 'finding' && c.finding.policyViolations?.length,
    )!;
    expect(finding.kind).toBe('finding');
    expect(finding.kind === 'finding' && finding.description).toMatch(/policy: /);
  });

  it('is empty when nothing is visible', () => {
    const noCritical = result.findings.filter((f) => f.severity !== 'critical');
    expect(buildTree({ ...result, findings: noCritical }, 'critical')).toEqual([]);
  });
});

describe('summarizeScan', () => {
  it('summarizes counts and policy status', () => {
    expect(summarizeScan(result, 'low')).toMatchObject({
      count: 6,
      severity: 'critical',
      status: 'pass',
    });
    expect(summarizeScan(result, 'low').text).toMatch(/^6 issues in \d+ packages$/);
    expect(summarizeScan(withPolicy, 'low').text).toContain('policy failed');
    expect(summarizeScan(result, 'critical')).toMatchObject({ count: 1, severity: 'critical' });
    const quiet = { ...result, findings: result.findings.filter((f) => f.severity !== 'critical') };
    expect(summarizeScan(quiet, 'critical')).toMatchObject({
      count: 0,
      text: expect.stringMatching(/^no issues/),
    });
    expect(summarizeScan({ ...withPolicy, status: 'warn' }, 'low').text).toContain(
      'policy warnings',
    );
    const one = { ...result, findings: result.findings.slice(0, 1) };
    expect(summarizeScan(one, 'info').text).toMatch(/^1 issue in/);
  });
});

describe('fixedVersionEdit', () => {
  const apply = (line: string, name: string, fixed: string, file: string) => {
    const startCol = line.indexOf(name);
    const edit = fixedVersionEdit(
      line,
      { name, range: { startCol, endCol: startCol + name.length } },
      fixed,
      file,
    );
    return edit && line.slice(0, edit.startCol) + edit.newText + line.slice(edit.endCol);
  };

  it('keeps npm range operators', () => {
    expect(apply('    "lodash": "^4.17.15",', 'lodash', '4.17.21', '/p/package.json')).toBe(
      '    "lodash": "^4.17.21",',
    );
    expect(apply('"a": "~1.0.0"', 'a', '1.0.5', '/p/package.json')).toBe('"a": "~1.0.5"');
    expect(apply('"a" : "1.0.0"', 'a', '1.0.5', '/p/package.json')).toBe('"a" : "1.0.5"');
  });

  it('skips npm specs it cannot safely rewrite', () => {
    expect(apply('"a": "latest"', 'a', '2.0.0', '/p/package.json')).toBeUndefined();
    expect(apply('"a": ">=1 <2"', 'a', '2.0.0', '/p/package.json')).toBeUndefined();
    expect(apply('"a": 1', 'a', '2.0.0', '/p/package.json')).toBeUndefined();
  });

  it('rewrites pip requirement specs', () => {
    expect(apply('flask==0.12  # pinned', 'flask', '0.12.3', '/p/requirements.txt')).toBe(
      'flask==0.12.3  # pinned',
    );
    expect(
      apply(
        'flask[async]>=0.10,<1; python_version>"3"',
        'flask',
        '0.12.3',
        '/p/requirements-dev.txt',
      ),
    ).toBe('flask[async]>=0.12.3; python_version>"3"');
    expect(apply('flask', 'flask', '1.0', '/p/requirements.txt')).toBe('flask>=1.0');
    expect(
      apply('flask @ https://example.invalid/f.whl', 'flask', '1.0', '/p/requirements.txt'),
    ).toBeUndefined();
    expect(apply('flask = "^1"', 'flask', '1.0', '/p/pyproject.toml')).toBeUndefined();
  });
});
