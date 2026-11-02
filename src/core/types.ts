export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = [
  'network',
  'exfiltration',
  'exec',
  'secrets-fs',
  'env-access',
  'obfuscation',
  'install-hook',
  'crypto-mining',
  'dynamic-code',
  'persistence',
  'vulnerability',
  'reputation',
] as const;
export type Category = (typeof CATEGORIES)[number];

export const LANGUAGES = [
  'javascript',
  'typescript',
  'python',
  'go',
  'rust',
  'java',
  'php',
  'shell',
  'json',
] as const;
export type Language = (typeof LANGUAGES)[number];

export type EcosystemId = 'npm' | 'pypi' | 'go' | 'cargo' | 'maven' | 'composer';

/** Zero-based, end-exclusive range inside a text file. */
export interface SourceRange {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
}

export interface PackageRef {
  ecosystem: EcosystemId;
  name: string;
  version: string;
}

/** A dependency as written in a manifest (package.json, requirements.txt, ...). */
export interface DeclaredDep {
  ecosystem: EcosystemId;
  name: string;
  versionSpec: string;
  manifestPath: string;
  /** Where the dependency name appears in the manifest; diagnostics anchor here. */
  range: SourceRange;
  isDev: boolean;
  /** Inline ignore markers: specific rule ids/globs, or 'all'. */
  ignoredRules?: string[] | 'all';
}

/** A dependency resolved to an exact version and, when installed, a path on disk. */
export interface ResolvedDep extends PackageRef {
  /** Absolute path of the installed package root; undefined when not installed. */
  installPath?: string;
  direct: boolean;
  isDev: boolean;
  /** The manifest entry this dep came from (for transitive deps: the direct dep that pulled it in). */
  declared?: DeclaredDep;
  /** Chain of package names from the direct dependency down to this one (exclusive). */
  via?: string[];
}

export type FindingSource = 'code' | 'install-hook' | 'osv' | 'reputation';

export interface FindingLocation {
  /** Absolute file path. */
  file: string;
  range: SourceRange;
}

export interface Finding {
  /** Stable id: see makeFindingId(). */
  id: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  message: string;
  source: FindingSource;
  package: PackageRef;
  location?: FindingLocation;
  /** Trimmed snippet of the matching code (max ~200 chars). */
  evidence?: string;
  references?: string[];
  /** For vulnerabilities: the version that fixes it, when known. */
  fixedVersion?: string;
  /** Set when an allowlist/ignore entry matched; suppressed findings are kept but hidden by default. */
  suppressed?: { reason: string };
  /** Names of policies this finding violates. */
  policyViolations?: string[];
}

export interface ScanLimits {
  maxFilesPerPackage: number;
  maxFileSizeBytes: number;
}

export const DEFAULT_LIMITS: ScanLimits = {
  maxFilesPerPackage: 2000,
  maxFileSizeBytes: 1024 * 1024,
};

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function maxSeverity(list: readonly Severity[]): Severity | undefined {
  let best: Severity | undefined;
  for (const s of list) {
    if (best === undefined || severityRank(s) > severityRank(best)) best = s;
  }
  return best;
}
