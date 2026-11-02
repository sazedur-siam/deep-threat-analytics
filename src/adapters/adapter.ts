import type { DeclaredDep, EcosystemId, Language, ResolvedDep, ScanLimits } from '../core/types';

export interface AdapterContext {
  /** Workspace trust. When false, adapters must not spawn processes. */
  trusted: boolean;
  includeDev: boolean;
  scanTransitive: boolean;
  /** Python only: explicit interpreter path from settings. */
  pythonInterpreter?: string;
  signal?: AbortSignal;
}

export interface EcosystemAdapter {
  readonly id: EcosystemId;
  /** Ecosystem name used by the OSV.dev API ('npm', 'PyPI', ...). */
  readonly osvEcosystem: string;
  /** Glob patterns (relative to a workspace folder) that locate manifests. */
  readonly manifestGlobs: readonly string[];

  /** True when this adapter handles the given manifest path. */
  matches(manifestPath: string): boolean;

  /** Pure parse of a manifest's text. Must not touch the filesystem. */
  parseManifest(manifestPath: string, text: string): DeclaredDep[];

  /**
   * Resolve declared deps to exact versions and install paths using lockfiles and the
   * on-disk install (node_modules, site-packages, ...). Includes transitive deps when
   * ctx.scanTransitive is set. Deps that are not installed are returned without installPath.
   */
  resolve(
    manifestPath: string,
    declared: DeclaredDep[],
    ctx: AdapterContext,
  ): Promise<ResolvedDep[]>;

  /** Absolute paths of the dependency's source files worth scanning, honoring limits. */
  listSourceFiles(dep: ResolvedDep, limits: ScanLimits): Promise<string[]>;

  /** Language of a file for rule selection, or undefined to skip it. */
  languageOf(file: string): Language | undefined;
}
