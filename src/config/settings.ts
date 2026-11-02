import { SEVERITIES, type ScanLimits, type Severity } from '../core/types';

/** VS Code diagnostic severity names a finding severity can map to. */
export const DIAGNOSTIC_LEVELS = ['error', 'warning', 'information', 'hint'] as const;
export type DiagnosticLevel = (typeof DIAGNOSTIC_LEVELS)[number];

export interface DepThreatSettings {
  scanTransitive: boolean;
  includeDevDependencies: boolean;
  /** Findings below this severity are dropped from the UI. */
  minSeverity: Severity;
  severityMapping: Record<Severity, DiagnosticLevel>;
  /** Globs for manifests to skip. */
  exclude: string[];
  maxFileSizeKB: number;
  maxFilesPerPackage: number;
  concurrency: number;
  /** Extra rule directories. Security-sensitive. */
  rulesPaths: string[];
  /** Explicit Python interpreter. Security-sensitive. */
  pythonInterpreterPath: string;
  /** Opt-in network lookups. Security-sensitive. */
  online: { osv: boolean; registryMetadata: boolean };
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const defaults: DepThreatSettings = {
  scanTransitive: true,
  includeDevDependencies: false,
  minSeverity: 'low',
  severityMapping: {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'information',
    info: 'hint',
  },
  exclude: ['**/node_modules/**', '**/.venv/**', '**/venv/**', '**/site-packages/**'],
  maxFileSizeKB: 1024,
  maxFilesPerPackage: 2000,
  concurrency: 4,
  rulesPaths: [],
  pythonInterpreterPath: '',
  online: { osv: false, registryMetadata: false },
};

/** Frozen defaults; readSettings always returns fresh, mutable copies. */
export const DEFAULT_SETTINGS: Readonly<DepThreatSettings> = deepFreeze(defaults);

/** Configuration section all keys live under. */
export const SETTINGS_SECTION = 'depthreat';

/** Field of DepThreatSettings (dotted for nested fields) → key under the `depthreat` section. */
export const SETTING_KEYS = {
  scanTransitive: 'scanTransitive',
  includeDevDependencies: 'includeDevDependencies',
  minSeverity: 'minSeverity',
  severityMapping: 'severityMapping',
  exclude: 'exclude',
  maxFileSizeKB: 'maxFileSizeKB',
  maxFilesPerPackage: 'maxFilesPerPackage',
  concurrency: 'concurrency',
  rulesPaths: 'rulesPaths',
  pythonInterpreterPath: 'python.interpreterPath',
  'online.osv': 'online.osv.enabled',
  'online.registryMetadata': 'online.registryMetadata.enabled',
} as const;

export type SettingField = keyof typeof SETTING_KEYS;

/**
 * Keys that can point at executables or rule code, or make network calls. In untrusted
 * workspaces only user-level (global) values are honored for these.
 */
export const SECURITY_SENSITIVE_KEYS: readonly string[] = Object.freeze([
  SETTING_KEYS.rulesPaths,
  SETTING_KEYS.pythonInterpreterPath,
  SETTING_KEYS['online.osv'],
  SETTING_KEYS['online.registryMetadata'],
]);

/** Value of one setting at each configuration level, like vscode's `inspect()` result. */
export interface SettingInspection {
  defaultValue?: unknown;
  globalValue?: unknown;
  workspaceValue?: unknown;
  workspaceFolderValue?: unknown;
}

/**
 * Where settings come from. `vscode.workspace.getConfiguration('depthreat')` satisfies this
 * interface structurally, so the extension can pass it straight in.
 */
export interface SettingsSource {
  inspect(key: string): SettingInspection | undefined;
}

export const LIMITS = Object.freeze({
  maxFileSizeKB: { min: 1, max: 100 * 1024 },
  maxFilesPerPackage: { min: 1, max: 100_000 },
  concurrency: { min: 1, max: 32 },
});

type Validator<T> = (value: unknown) => T | undefined;

const isBoolean: Validator<boolean> = (v) => (typeof v === 'boolean' ? v : undefined);

const isSeverity: Validator<Severity> = (v) =>
  typeof v === 'string' && (SEVERITIES as readonly string[]).includes(v)
    ? (v as Severity)
    : undefined;

const isDiagnosticLevel: Validator<DiagnosticLevel> = (v) =>
  typeof v === 'string' && (DIAGNOSTIC_LEVELS as readonly string[]).includes(v)
    ? (v as DiagnosticLevel)
    : undefined;

const isString: Validator<string> = (v) => (typeof v === 'string' ? v.trim() : undefined);

/** Arrays keep their non-empty string entries; anything else is invalid. */
const isStringList: Validator<string[]> = (v) =>
  Array.isArray(v)
    ? v.filter((s): s is string => typeof s === 'string' && s.trim() !== '').map((s) => s.trim())
    : undefined;

function clampedInt(min: number, max: number): Validator<number> {
  return (v) => {
    if (typeof v !== 'number' || !Number.isFinite(v)) return undefined;
    return Math.min(max, Math.max(min, Math.round(v)));
  };
}

/**
 * Candidate values for a key, highest precedence first. Untrusted workspaces only expose the
 * user-level value of security-sensitive keys.
 */
function layers(source: SettingsSource, key: string, trusted: boolean): unknown[] {
  const info = source.inspect(key);
  if (!info) return [];
  if (!trusted && SECURITY_SENSITIVE_KEYS.includes(key)) return [info.globalValue];
  return [info.workspaceFolderValue, info.workspaceValue, info.globalValue];
}

/** The highest-precedence value that validates; invalid layers fall through to lower ones. */
function pick<T>(
  source: SettingsSource,
  key: string,
  trusted: boolean,
  validate: Validator<T>,
  fallback: T,
): T {
  for (const raw of layers(source, key, trusted)) {
    if (raw === undefined || raw === null) continue;
    const value = validate(raw);
    if (value !== undefined) return value;
  }
  return fallback;
}

/** Object settings merge per property across levels (as VS Code does); each value is validated. */
function readSeverityMapping(
  source: SettingsSource,
  trusted: boolean,
): Record<Severity, DiagnosticLevel> {
  const mapping = { ...DEFAULT_SETTINGS.severityMapping };
  for (const raw of layers(source, SETTING_KEYS.severityMapping, trusted).reverse()) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
    for (const sev of SEVERITIES) {
      const level = isDiagnosticLevel((raw as Record<string, unknown>)[sev]);
      if (level) mapping[sev] = level;
    }
  }
  return mapping;
}

/**
 * Read, validate and clamp all settings. Values of the wrong type fall back to the next
 * configuration level and finally to DEFAULT_SETTINGS. When `trusted` is false,
 * workspace and workspace-folder values of SECURITY_SENSITIVE_KEYS are ignored.
 */
export function readSettings(source: SettingsSource, trusted: boolean): DepThreatSettings {
  const d = DEFAULT_SETTINGS;
  const get = <T>(key: string, validate: Validator<T>, fallback: T): T =>
    pick(source, key, trusted, validate, fallback);
  const { maxFileSizeKB, maxFilesPerPackage, concurrency } = LIMITS;
  return {
    scanTransitive: get(SETTING_KEYS.scanTransitive, isBoolean, d.scanTransitive),
    includeDevDependencies: get(
      SETTING_KEYS.includeDevDependencies,
      isBoolean,
      d.includeDevDependencies,
    ),
    minSeverity: get(SETTING_KEYS.minSeverity, isSeverity, d.minSeverity),
    severityMapping: readSeverityMapping(source, trusted),
    exclude: get(SETTING_KEYS.exclude, isStringList, [...d.exclude]),
    maxFileSizeKB: get(
      SETTING_KEYS.maxFileSizeKB,
      clampedInt(maxFileSizeKB.min, maxFileSizeKB.max),
      d.maxFileSizeKB,
    ),
    maxFilesPerPackage: get(
      SETTING_KEYS.maxFilesPerPackage,
      clampedInt(maxFilesPerPackage.min, maxFilesPerPackage.max),
      d.maxFilesPerPackage,
    ),
    concurrency: get(
      SETTING_KEYS.concurrency,
      clampedInt(concurrency.min, concurrency.max),
      d.concurrency,
    ),
    rulesPaths: get(SETTING_KEYS.rulesPaths, isStringList, [...d.rulesPaths]),
    pythonInterpreterPath: get(
      SETTING_KEYS.pythonInterpreterPath,
      isString,
      d.pythonInterpreterPath,
    ),
    online: {
      osv: get(SETTING_KEYS['online.osv'], isBoolean, d.online.osv),
      registryMetadata: get(
        SETTING_KEYS['online.registryMetadata'],
        isBoolean,
        d.online.registryMetadata,
      ),
    },
  };
}

/** Byte/file limits for scanners, derived from settings. */
export function scanLimitsFrom(settings: DepThreatSettings): ScanLimits {
  return {
    maxFilesPerPackage: settings.maxFilesPerPackage,
    maxFileSizeBytes: settings.maxFileSizeKB * 1024,
  };
}
