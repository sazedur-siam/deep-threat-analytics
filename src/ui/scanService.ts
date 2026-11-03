import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import type { EcosystemAdapter } from '../adapters/adapter';
import { goAdapter } from '../adapters/golang';
import { javaAdapter } from '../adapters/java';
import { npmAdapter } from '../adapters/npm';
import { phpAdapter } from '../adapters/php';
import { pythonAdapter } from '../adapters/python';
import { rustAdapter } from '../adapters/rust';
import {
  extensionsManifestLabel,
  isExtensionsManifest,
  tildify,
  vscodeExtensionsAdapter,
} from '../adapters/vscodeExtensions';
import {
  CONFIG_DIR,
  EMPTY_CONFIG,
  loadProjectConfig,
  type ProjectConfig,
} from '../config/projectConfig';
import { readSettings, SETTINGS_SECTION, type DepThreatSettings } from '../config/settings';
import { ScanCache } from '../core/cache';
import { scanManifests, type OnlineCheck, type ScanResult } from '../core/engine';
import { compileRule, loadRules } from '../rules/loader';

export const ADAPTERS: readonly EcosystemAdapter[] = [
  npmAdapter,
  pythonAdapter,
  goAdapter,
  rustAdapter,
  phpAdapter,
  javaAdapter,
  // No manifest globs: only takes part when Scan Installed Extensions passes extensions.json in.
  vscodeExtensionsAdapter,
];

/** Workspace-relative path, or `~/…` for files outside the workspace (installed extensions). */
export function displayPath(file: string): string {
  const rel = vscode.workspace.asRelativePath(file);
  return path.isAbsolute(rel) ? tildify(rel, os.homedir()) : rel;
}

/** Findings-tree label for a manifest. */
export function manifestLabel(manifestPath: string): string {
  return isExtensionsManifest(manifestPath)
    ? extensionsManifestLabel(manifestPath, os.homedir())
    : displayPath(manifestPath);
}

/** Builds the online checks enabled in settings (filled in by the OSV/reputation layer). */
export type OnlineFactory = (
  settings: DepThreatSettings,
  adapters: readonly EcosystemAdapter[],
) => OnlineCheck[];

export function currentSettings(): DepThreatSettings {
  return readSettings(
    vscode.workspace.getConfiguration(SETTINGS_SECTION),
    vscode.workspace.isTrusted,
  );
}

function mergeConfigs(configs: ProjectConfig[]): ProjectConfig {
  return {
    allowlist: {
      packages: configs.flatMap((c) => c.allowlist.packages),
      rules: configs.flatMap((c) => c.allowlist.rules),
    },
    ignore: configs.flatMap((c) => c.ignore),
    severityOverrides: configs.flatMap((c) => c.severityOverrides),
    policies: configs.flatMap((c) => c.policies),
  };
}

export class ScanService implements vscode.Disposable {
  private readonly emitter = new vscode.EventEmitter<ScanResult>();
  readonly onDidScan = this.emitter.event;
  lastResult: ScanResult | undefined;
  private lastTargets: vscode.Uri[] | undefined;
  private running: AbortController | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
    readonly cache: ScanCache,
    private readonly online: OnlineFactory = () => [],
  ) {}

  dispose(): void {
    this.running?.abort();
    this.emitter.dispose();
  }

  /** Manifests in the workspace, honoring the exclude setting. */
  async discover(settings: DepThreatSettings): Promise<vscode.Uri[]> {
    const include = `{${ADAPTERS.flatMap((a) => a.manifestGlobs).join(',')}}`;
    const exclude = settings.exclude.length ? `{${settings.exclude.join(',')}}` : null;
    const found = await vscode.workspace.findFiles(include, exclude);
    return found
      .filter((uri) => ADAPTERS.some((a) => a.matches(uri.fsPath)))
      .sort((a, b) => a.fsPath.localeCompare(b.fsPath));
  }

  private async loadRuleSet(settings: DepThreatSettings) {
    const folders = vscode.workspace.workspaceFolders ?? [];
    const base = folders[0]?.uri.fsPath ?? '';
    const dirs = [
      this.context.asAbsolutePath(path.join('rules', 'builtin')),
      ...settings.rulesPaths.map((p) => path.resolve(base, p)),
      // A repository's own rules could disable detections, so only trusted workspaces use them.
      ...(vscode.workspace.isTrusted
        ? folders.map((f) => path.join(f.uri.fsPath, CONFIG_DIR, 'rules'))
        : []),
    ];
    const loaded = await loadRules(dirs);
    for (const e of loaded.errors) {
      this.output.appendLine(
        `Rule error in ${e.file}${e.index === undefined ? '' : ` (rule #${e.index + 1})`}: ${e.message}`,
      );
    }
    return loaded;
  }

  private async loadConfig(): Promise<ProjectConfig> {
    // An untrusted repository could allowlist its own malicious dependencies.
    if (!vscode.workspace.isTrusted) return EMPTY_CONFIG;
    const configs: ProjectConfig[] = [];
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
      const { config, errors, path: file } = await loadProjectConfig(folder.uri.fsPath);
      for (const e of errors)
        this.output.appendLine(
          `Config error in ${file}${e.path ? ` at ${e.path}` : ''}: ${e.message}`,
        );
      configs.push(config);
    }
    return mergeConfigs(configs);
  }

  /** Scan the given manifests, or the whole workspace. Returns undefined when cancelled. */
  async scan(
    targets?: vscode.Uri[],
    options: { silent?: boolean } = {},
  ): Promise<ScanResult | undefined> {
    this.running?.abort();
    const ctrl = new AbortController();
    this.running = ctrl;
    const settings = currentSettings();
    const run = async (
      progress: vscode.Progress<{ message?: string; increment?: number }>,
      token: vscode.CancellationToken,
    ) => {
      token.onCancellationRequested(() => ctrl.abort());
      const manifests = targets ?? (await this.discover(settings));
      this.lastTargets = targets;
      const [rules, projectConfig] = await Promise.all([
        this.loadRuleSet(settings),
        this.loadConfig(),
      ]);
      await this.cache.load();
      return scanManifests(
        manifests.map((u) => u.fsPath),
        {
          adapters: ADAPTERS,
          rules: rules.rules.map(compileRule),
          rulesHash: rules.hash,
          settings,
          projectConfig,
          trusted: vscode.workspace.isTrusted,
          cache: this.cache,
          online: this.online(settings, ADAPTERS),
          signal: ctrl.signal,
          onProgress: (p) =>
            progress.report({
              message:
                p.phase === 'resolve'
                  ? 'Resolving dependencies…'
                  : p.phase === 'scan'
                    ? `Scanning packages ${p.done}/${p.total}`
                    : 'Checking online sources…',
            }),
        },
      );
    };
    try {
      const result = options.silent
        ? await run({ report: () => undefined }, new vscode.CancellationTokenSource().token)
        : await vscode.window.withProgress(
            {
              location: vscode.ProgressLocation.Notification,
              title: 'DepThreat',
              cancellable: true,
            },
            run,
          );
      for (const e of result.errors) this.output.appendLine(e);
      this.output.appendLine(
        `Scanned ${result.manifests.length} manifests, ${result.stats.packages} packages ` +
          `(${result.stats.cached} cached) in ${result.stats.durationMs} ms.`,
      );
      this.lastResult = result;
      this.emitter.fire(result);
      return result;
    } catch (e) {
      if (ctrl.signal.aborted) {
        this.output.appendLine('Scan cancelled.');
        return undefined;
      }
      this.output.appendLine(`Scan failed: ${(e as Error).stack ?? String(e)}`);
      throw e;
    } finally {
      if (this.running === ctrl) this.running = undefined;
    }
  }

  /** Re-run the last scan (e.g. after editing ignores); cached packages make this fast. */
  rescan(): Promise<ScanResult | undefined> {
    return this.scan(this.lastTargets, { silent: true });
  }
}
