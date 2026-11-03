import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { pythonAdapter } from '../../../src/adapters/python';
import { DEFAULT_LIMITS, type Finding } from '../../../src/core/types';
import { compileRule, loadRules } from '../../../src/rules/loader';
import { scanPackageCode } from '../../../src/scanners/codeScanner';
import { scanInstallHooks } from '../../../src/scanners/installHooks';

const SAMPLE = path.resolve(__dirname, '../../fixtures/py-sample');
const byPackage = new Map<string, Finding[]>();

beforeAll(async () => {
  const rules = (await loadRules([path.resolve(__dirname, '../../../rules/builtin')])).rules.map(
    compileRule,
  );
  const manifest = path.join(SAMPLE, 'requirements.txt');
  const declared = pythonAdapter.parseManifest(manifest, await readFile(manifest, 'utf8'));
  const deps = await pythonAdapter.resolve(manifest, declared, {
    trusted: false,
    includeDev: false,
    scanTransitive: true,
  });
  for (const dep of deps) {
    const files = await pythonAdapter.listSourceFiles(dep, DEFAULT_LIMITS);
    byPackage.set(dep.name, [
      ...(await scanPackageCode({
        dep,
        files,
        languageOf: pythonAdapter.languageOf,
        rules,
        maxFileSizeBytes: DEFAULT_LIMITS.maxFileSizeBytes,
      })),
      ...(await scanInstallHooks(dep, files)),
    ]);
  }
});

const ruleIds = (name: string) => (byPackage.get(name) ?? []).map((f) => f.ruleId).sort();

describe('py-sample fixture end to end', () => {
  it('flags environment exfiltration', () => {
    expect(ruleIds('evil-exfil')).toEqual([
      'env-access/enumerate-env',
      'exfiltration/python-env-to-network',
    ]);
  });

  it('flags the shell payload and the startup .pth hook', () => {
    expect(ruleIds('evil-setup')).toEqual([
      'dynamic-code/download-and-execute',
      'exec/python-shell',
      'exec/python-shell',
      'install-hook/python-pth-exec',
    ]);
    const pth = byPackage
      .get('evil-setup')!
      .find((f) => f.ruleId === 'install-hook/python-pth-exec')!;
    expect(pth.severity).toBe('critical');
  });

  it('reports nothing for clean packages', () => {
    for (const name of ['clean-lib', 'tiny-py-dep', 'not-installed-py']) {
      expect(ruleIds(name), name).toEqual([]);
    }
  });
});
