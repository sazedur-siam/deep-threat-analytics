import * as path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { npmAdapter } from '../../../src/adapters/npm';
import { vscodeExtensionsAdapter } from '../../../src/adapters/vscodeExtensions';
import { EMPTY_CONFIG } from '../../../src/config/projectConfig';
import { DEFAULT_SETTINGS } from '../../../src/config/settings';
import { scanManifests, type ScanResult } from '../../../src/core/engine';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { createPackageChecks } from '../../../src/scanners/packageChecks';
import { makeExtensionsDir } from '../../helpers/vscodeExtensions';

const FIXTURE = path.resolve(__dirname, '../../fixtures/vscode-extensions');
const DATA = path.resolve(__dirname, '../../../data');
const RAW_INVISIBLE = /[\p{Cf}\p{Co}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;
const fetchImpl = vi.fn();
let dir: string;
let result: ScanResult;

beforeAll(async () => {
  dir = await makeExtensionsDir(FIXTURE);
  const loaded = await loadRules([path.resolve(__dirname, '../../../rules/builtin')]);
  const adapters = [npmAdapter, vscodeExtensionsAdapter];
  // Every online check enabled: extensions must still never reach OSV or a registry.
  const settings = { ...DEFAULT_SETTINGS, online: { osv: true, registryMetadata: true } };
  result = await scanManifests([path.join(dir, 'extensions.json')], {
    adapters,
    rules: loaded.rules.map(compileRule),
    rulesHash: loaded.hash,
    settings,
    projectConfig: EMPTY_CONFIG,
    trusted: false,
    online: createPackageChecks(settings, adapters, DATA, fetchImpl),
  });
});

const ruleIds = (name: string) =>
  result.findings
    .filter((f) => f.package.name === name)
    .map((f) => f.ruleId)
    .sort();
const worst = (name: string, ruleId: string) =>
  result.findings.find((f) => f.package.name === name && f.ruleId === ruleId);

describe('installed-extensions fixture end to end', () => {
  it('scans every installed extension except DepThreat itself', () => {
    expect(result.errors).toEqual([]);
    expect(result.manifests.map((m) => m.ecosystem)).toEqual(['vscode']);
    expect(result.manifests[0]!.deps.map((d) => d.name)).toEqual([
      'glassworm-sample.color-theme-glow',
      'devtools-sample.ssh-helper',
      'esbenp.prettier-vscod',
      'clean-sample.word-count',
      'escape-sample.traversal',
    ]);
    // Four folders scanned; the path-traversal entry has no folder.
    expect(result.stats).toMatchObject({ packages: 5, scanned: 4 });
    expect(ruleIds('mdsazedurrahman.deep-threat-analytics')).toEqual([]);
    expect(ruleIds('escape-sample.traversal')).toEqual([]);
  });

  it('never sends extensions to OSV or a registry', () => {
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('flags the GlassWorm-like invisible payload and blockchain C2', () => {
    const ids = ruleIds('glassworm-sample.color-theme-glow');
    expect(ids).toContain('obfuscation/invisible-unicode-payload');
    expect(ids).toContain('network/blockchain-c2');
    const payload = worst(
      'glassworm-sample.color-theme-glow',
      'obfuscation/invisible-unicode-payload',
    );
    expect(payload).toMatchObject({ severity: 'critical', source: 'code' });
    expect(payload?.location?.file).toBe(
      path.join(dir, 'glassworm-sample.color-theme-glow-1.0.3', 'lib', 'extension.js'),
    );
    expect(payload?.evidence).not.toMatch(RAW_INVISIBLE);
  });

  it('flags the credential stealer, its startup activation, uninstall hook and bundled dropper', () => {
    const ids = ruleIds('devtools-sample.ssh-helper');
    for (const id of [
      'exfiltration/secret-file-to-webhook',
      'secrets-fs/ssh-keys',
      'install-hook/vscode-startup-activation',
      'install-hook/vscode-uninstall-script',
      'dynamic-code/download-and-execute',
    ]) {
      expect(ids, id).toContain(id);
    }
    expect(
      worst('devtools-sample.ssh-helper', 'exfiltration/secret-file-to-webhook')?.severity,
    ).toBe('critical');
    expect(
      worst('devtools-sample.ssh-helper', 'install-hook/vscode-uninstall-script')?.severity,
    ).toBe('high');
    const dropper = worst('devtools-sample.ssh-helper', 'dynamic-code/download-and-execute');
    expect(dropper?.location?.file).toBe(
      path.join(dir, 'devtools-sample.ssh-helper-0.2.0', 'node_modules', 'helper-lib', 'index.js'),
    );
  });

  it('flags the look-alike id and nothing else about it', () => {
    expect(ruleIds('esbenp.prettier-vscod')).toEqual(['reputation/typosquat']);
    expect(worst('esbenp.prettier-vscod', 'reputation/typosquat')?.title).toBe(
      'Possible typosquat of esbenp.prettier-vscode',
    );
  });

  it('reports nothing for the clean extension', () => {
    expect(ruleIds('clean-sample.word-count')).toEqual([]);
  });

  it('anchors every finding on its extension id in extensions.json', () => {
    const manifest = result.manifests[0]!;
    for (const dep of manifest.deps) {
      expect(dep.declared?.manifestPath).toBe(path.join(dir, 'extensions.json'));
    }
  });
});
