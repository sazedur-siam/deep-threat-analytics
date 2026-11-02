import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { npmAdapter } from '../../../src/adapters/npm';
import { DEFAULT_LIMITS, type Finding } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';
import { scanInstallHooks } from '../../../src/scanners/installHooks';

const SAMPLE = path.resolve(__dirname, '../../fixtures/npm-sample');
const byPackage = new Map<string, Finding[]>();

beforeAll(async () => {
  const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
    compileRule,
  );
  const manifest = path.join(SAMPLE, 'package.json');
  const declared = npmAdapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  const deps = await npmAdapter.resolve(manifest, declared, {
    trusted: true,
    includeDev: true,
    scanTransitive: true,
  });
  for (const dep of deps) {
    const files = await npmAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
    const findings = [
      ...(await scanPackageCode({
        dep,
        files,
        languageOf: npmAdapter.languageOf,
        rules,
        maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
      })),
      ...(await scanInstallHooks(dep, files)),
    ];
    byPackage.set(dep.name, findings);
  }
});

const ruleIds = (name: string) => (byPackage.get(name) ?? []).map((f) => f.ruleId).sort();

describe('npm-sample fixture end to end', () => {
  it('flags the env stealer as exfiltration', () => {
    expect(ruleIds('evil-env-stealer')).toEqual([
      'env-access/serialize-env',
      'exfiltration/env-to-network',
    ]);
    const exfil = byPackage
      .get('evil-env-stealer')!
      .find((f) => f.ruleId === 'exfiltration/env-to-network')!;
    expect(exfil.severity).toBe('high');
    expect(exfil.location?.file).toBe(path.join(SAMPLE, 'node_modules/evil-env-stealer/index.js'));
  });

  it('flags the install hook and the shell command it runs', () => {
    expect(ruleIds('evil-postinstall')).toEqual([
      'exec/node-child-process',
      'exec/node-child-process-shell',
      'install-hook/npm-lifecycle-script',
    ]);
  });

  it('reports nothing for clean packages', () => {
    for (const name of ['clean-utils', 'tiny-dep', 'dev-only-tool', 'not-installed']) {
      expect(ruleIds(name), name).toEqual([]);
    }
  });
});
