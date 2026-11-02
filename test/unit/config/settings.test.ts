import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SETTINGS,
  readSettings,
  scanLimitsFrom,
  SECURITY_SENSITIVE_KEYS,
  SETTING_KEYS,
  type SettingInspection,
  type SettingsSource,
} from '../../../src/config/settings';

function source(values: Record<string, SettingInspection>): SettingsSource {
  return { inspect: (key) => values[key] };
}

describe('readSettings', () => {
  it('returns defaults when nothing is set, as fresh copies', () => {
    const a = readSettings(source({}), true);
    expect(a).toEqual(DEFAULT_SETTINGS);
    a.exclude.push('x');
    expect(readSettings(source({}), true).exclude).not.toContain('x');
    expect(Object.isFrozen(DEFAULT_SETTINGS)).toBe(true);
  });

  it('prefers folder over workspace over user values', () => {
    const s = readSettings(
      source({
        minSeverity: {
          globalValue: 'high',
          workspaceValue: 'medium',
          workspaceFolderValue: 'info',
        },
        includeDevDependencies: { globalValue: true, workspaceValue: false },
        scanTransitive: { globalValue: false },
      }),
      true,
    );
    expect(s.minSeverity).toBe('info');
    expect(s.includeDevDependencies).toBe(false);
    expect(s.scanTransitive).toBe(false);
  });

  it('falls through invalid values to lower levels and defaults', () => {
    const s = readSettings(
      source({
        minSeverity: { workspaceValue: 'urgent', globalValue: 'high' },
        scanTransitive: { workspaceValue: 'yes' },
        exclude: { workspaceValue: 'not-a-list' },
        concurrency: { workspaceValue: Number.NaN },
        pythonInterpreterPath: { globalValue: 42 },
      }),
      true,
    );
    expect(s.minSeverity).toBe('high');
    expect(s.scanTransitive).toBe(true);
    expect(s.exclude).toEqual(DEFAULT_SETTINGS.exclude);
    expect(s.concurrency).toBe(4);
    expect(s.pythonInterpreterPath).toBe('');
  });

  it('clamps and rounds numbers and cleans string lists', () => {
    const s = readSettings(
      source({
        concurrency: { globalValue: 500 },
        maxFileSizeKB: { globalValue: 0 },
        maxFilesPerPackage: { globalValue: 12.6 },
        rulesPaths: { globalValue: [' /a ', '', 3, '/b'] },
        'python.interpreterPath': { globalValue: '  /usr/bin/python3 ' },
      }),
      true,
    );
    expect(s.concurrency).toBe(32);
    expect(s.maxFileSizeKB).toBe(1);
    expect(s.maxFilesPerPackage).toBe(13);
    expect(s.rulesPaths).toEqual(['/a', '/b']);
    expect(s.pythonInterpreterPath).toBe('/usr/bin/python3');
  });

  it('merges severity mapping per severity across levels', () => {
    const s = readSettings(
      source({
        severityMapping: {
          globalValue: { low: 'warning', medium: 'bogus' },
          workspaceValue: { low: 'error', critical: 'hint' },
          workspaceFolderValue: [],
        },
      }),
      true,
    );
    expect(s.severityMapping).toEqual({
      critical: 'hint',
      high: 'error',
      medium: 'warning',
      low: 'error',
      info: 'hint',
    });
  });

  it('ignores workspace values of security-sensitive keys when untrusted', () => {
    const values = {
      rulesPaths: { globalValue: ['/user'], workspaceValue: ['/evil'] },
      'python.interpreterPath': { workspaceValue: '/evil/python' },
      'online.osv.enabled': { workspaceFolderValue: true },
      'online.registryMetadata.enabled': { globalValue: true, workspaceValue: false },
      minSeverity: { workspaceValue: 'critical' },
    };
    const untrusted = readSettings(source(values), false);
    expect(untrusted.rulesPaths).toEqual(['/user']);
    expect(untrusted.pythonInterpreterPath).toBe('');
    expect(untrusted.online).toEqual({ osv: false, registryMetadata: true });
    expect(untrusted.minSeverity).toBe('critical');
    const trusted = readSettings(source(values), true);
    expect(trusted.rulesPaths).toEqual(['/evil']);
    expect(trusted.online.osv).toBe(true);
    expect(SECURITY_SENSITIVE_KEYS).toHaveLength(4);
  });

  it('derives scan limits', () => {
    expect(scanLimitsFrom(DEFAULT_SETTINGS)).toEqual({
      maxFilesPerPackage: 2000,
      maxFileSizeBytes: 1024 * 1024,
    });
  });
});

describe('package.json configuration', () => {
  const pkg = JSON.parse(
    readFileSync(path.resolve(__dirname, '../../../package.json'), 'utf8'),
  ) as { contributes: { configuration: { properties: Record<string, { default: unknown }> } } };
  const props = pkg.contributes.configuration.properties;

  it('contributes every setting with the same default', () => {
    for (const [field, key] of Object.entries(SETTING_KEYS)) {
      const expected = field
        .split('.')
        .reduce<unknown>((v, k) => (v as Record<string, unknown>)[k], DEFAULT_SETTINGS);
      expect(props[`depthreat.${key}`]?.default, key).toEqual(expected);
    }
    expect(Object.keys(props)).toHaveLength(Object.keys(SETTING_KEYS).length);
  });
});
