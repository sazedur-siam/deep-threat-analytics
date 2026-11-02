import { readFile as fsReadFile } from 'node:fs/promises';
import type { AdapterContext, EcosystemAdapter } from '../adapters/adapter';
import type { ProjectConfig } from '../config/projectConfig';
import { scanLimitsFrom, type DepThreatSettings } from '../config/settings';
import { evaluatePolicies, type PolicyStatus, type PolicyViolation } from '../policy/policy';
import { applySuppressions, type InlineIgnores } from '../policy/suppress';
import type { CompiledRule } from '../rules/loader';
import { scanPackageCode } from '../scanners/codeScanner';
import { scanInstallHooks } from '../scanners/installHooks';
import { ScanCache } from './cache';
import { mapLimit } from './concurrency';
import { packageKey } from './findings';
import type { DeclaredDep, Finding, ResolvedDep } from './types';

export interface ScanProgress {
  phase: 'resolve' | 'scan' | 'online';
  done: number;
  total: number;
  message?: string;
}

/** Extra package-level checks (OSV, registry reputation); errors are reported, not thrown. */
export type OnlineCheck = (
  deps: ResolvedDep[],
  signal?: AbortSignal,
) => Promise<{ findings: Finding[]; errors: string[] }>;

export interface EngineOptions {
  adapters: readonly EcosystemAdapter[];
  rules: CompiledRule[];
  rulesHash: string;
  settings: DepThreatSettings;
  projectConfig: ProjectConfig;
  trusted: boolean;
  cache?: ScanCache;
  online?: OnlineCheck[];
  signal?: AbortSignal;
  onProgress?: (p: ScanProgress) => void;
  readFile?: (file: string) => Promise<string>;
}

export interface ManifestResult {
  manifestPath: string;
  ecosystem: EcosystemAdapter['id'];
  declared: DeclaredDep[];
  deps: ResolvedDep[];
  error?: string;
}

export interface ScanResult {
  manifests: ManifestResult[];
  /** All findings after suppressions and policies; suppressed ones carry `suppressed`. */
  findings: Finding[];
  violations: PolicyViolation[];
  status: PolicyStatus;
  /** Non-fatal problems (unreadable manifest, failed online lookup, ...). */
  errors: string[];
  stats: { packages: number; scanned: number; cached: number; durationMs: number };
}

function depKey(dep: ResolvedDep): string {
  return `${packageKey(dep)}|${dep.installPath ?? ''}`;
}

function inlineIgnores(manifests: ManifestResult[]): InlineIgnores {
  const out: InlineIgnores = new Map();
  for (const m of manifests) {
    for (const d of m.declared) {
      if (d.ignoredRules) out.set(`${d.ecosystem}:${d.name}`, d.ignoredRules);
    }
  }
  return out;
}

/**
 * Scan a set of manifests: resolve each one, scan every unique installed package once (with
 * caching), run optional online checks, then apply suppressions and policies. Never executes
 * dependency code.
 */
export async function scanManifests(
  manifestPaths: readonly string[],
  opts: EngineOptions,
): Promise<ScanResult> {
  const started = Date.now();
  const read = opts.readFile ?? ((f: string) => fsReadFile(f, 'utf8'));
  const { settings, signal } = opts;
  const errors: string[] = [];
  const ctx: AdapterContext = {
    trusted: opts.trusted,
    includeDev: settings.includeDevDependencies,
    scanTransitive: settings.scanTransitive,
    ...(settings.pythonInterpreterPath
      ? { pythonInterpreter: settings.pythonInterpreterPath }
      : {}),
    ...(signal ? { signal } : {}),
  };

  const manifests: ManifestResult[] = [];
  for (const [i, manifestPath] of manifestPaths.entries()) {
    signal?.throwIfAborted();
    opts.onProgress?.({
      phase: 'resolve',
      done: i,
      total: manifestPaths.length,
      message: manifestPath,
    });
    const adapter = opts.adapters.find((a) => a.matches(manifestPath));
    if (!adapter) continue;
    try {
      const declared = adapter.parseManifest(manifestPath, await read(manifestPath));
      const deps = await adapter.resolve(manifestPath, declared, ctx);
      manifests.push({ manifestPath, ecosystem: adapter.id, declared, deps });
    } catch (e) {
      if (signal?.aborted) throw e;
      const message = `Could not analyze ${manifestPath}: ${(e as Error).message}`;
      errors.push(message);
      manifests.push({
        manifestPath,
        ecosystem: adapter.id,
        declared: [],
        deps: [],
        error: message,
      });
    }
  }

  const unique = new Map<string, { dep: ResolvedDep; adapter: EcosystemAdapter }>();
  for (const m of manifests) {
    const adapter = opts.adapters.find((a) => a.id === m.ecosystem) as EcosystemAdapter;
    for (const dep of m.deps)
      if (!unique.has(depKey(dep))) unique.set(depKey(dep), { dep, adapter });
  }
  const installed = [...unique.values()].filter((u) => u.dep.installPath);
  const limits = scanLimitsFrom(settings);
  let cached = 0;
  let done = 0;

  const perPackage = await mapLimit(
    installed,
    settings.concurrency,
    async ({ dep, adapter }) => {
      const key = ScanCache.key(dep, opts.rulesHash, dep.installPath);
      const hit = opts.cache?.get(key);
      let findings: Finding[];
      if (hit) {
        cached++;
        findings = hit;
      } else {
        const files = await adapter.listSourceFiles(dep, limits);
        findings = [
          ...(await scanPackageCode({
            dep,
            files,
            languageOf: (f) => adapter.languageOf(f),
            rules: opts.rules,
            maxFileSizeBytes: limits.maxFileSizeBytes,
            ...(signal ? { signal } : {}),
            readFile: read,
          })),
          ...(await scanInstallHooks(dep, files, read)),
        ];
        opts.cache?.set(key, findings);
      }
      opts.onProgress?.({
        phase: 'scan',
        done: ++done,
        total: installed.length,
        message: dep.name,
      });
      return findings;
    },
    signal,
  );

  const findings = perPackage.flat();
  for (const [i, check] of (opts.online ?? []).entries()) {
    signal?.throwIfAborted();
    opts.onProgress?.({ phase: 'online', done: i, total: opts.online!.length });
    const result = await check(
      [...unique.values()].map((u) => u.dep),
      signal,
    );
    findings.push(...result.findings);
    errors.push(...result.errors);
  }

  await opts.cache
    ?.save()
    .catch((e: Error) => errors.push(`Could not save scan cache: ${e.message}`));

  const suppressed = applySuppressions(findings, opts.projectConfig, inlineIgnores(manifests));
  const policy = evaluatePolicies(suppressed, opts.projectConfig.policies);
  return {
    manifests,
    findings: policy.findings,
    violations: policy.violations,
    status: policy.status,
    errors,
    stats: {
      packages: unique.size,
      scanned: installed.length - cached,
      cached,
      durationMs: Date.now() - started,
    },
  };
}
