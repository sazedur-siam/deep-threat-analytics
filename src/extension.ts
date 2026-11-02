import * as path from 'node:path';
import * as vscode from 'vscode';
import { ScanCache } from './core/cache';
import type { ScanResult } from './core/engine';
import { createPackageChecks } from './scanners/packageChecks';
import { registerCommands } from './ui/commands';
import { DiagnosticsPresenter, registerCodeActions, registerHover } from './ui/diagnostics';
import { buildTree, summarizeScan, type TreeNode } from './ui/model';
import { currentSettings, ScanService } from './ui/scanService';
import { FindingsTree, StatusBar } from './ui/treeView';

/** Returned from activate() so integration tests can inspect results. */
export interface DepThreatApi {
  scan(targets?: vscode.Uri[]): Promise<ScanResult | undefined>;
  readonly lastResult: ScanResult | undefined;
  readonly treeRoots: readonly TreeNode[];
}

export function activate(context: vscode.ExtensionContext): DepThreatApi {
  const output = vscode.window.createOutputChannel('Deep Threat Analytics');
  const cache = new ScanCache(path.join(context.globalStorageUri.fsPath, 'scan-cache.json'));
  const service = new ScanService(context, output, cache, (settings, adapters) =>
    createPackageChecks(settings, adapters, context.asAbsolutePath('data')),
  );
  const diagnostics = new DiagnosticsPresenter();
  const tree = new FindingsTree();
  const view = vscode.window.createTreeView('depthreat.findings', {
    treeDataProvider: tree,
    showCollapseAll: true,
  });
  const status = new StatusBar();

  const render = (result: ScanResult) => {
    const settings = currentSettings();
    diagnostics.update(result, settings);
    tree.update(buildTree(result, settings.minSeverity, (p) => vscode.workspace.asRelativePath(p)));
    const summary = summarizeScan(result, settings.minSeverity);
    status.show(summary);
    view.message = summary.count
      ? undefined
      : `No issues found in ${result.stats.packages} packages.`;
  };

  context.subscriptions.push(
    output,
    service,
    diagnostics,
    view,
    status,
    registerHover(diagnostics),
    registerCodeActions(diagnostics),
    ...registerCommands(service, tree, view),
    service.onDidScan(render),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('depthreat') && service.lastResult) render(service.lastResult);
    }),
  );

  return {
    scan: async (targets) => {
      status.scanning();
      try {
        return await service.scan(targets, { silent: true });
      } finally {
        if (!service.lastResult) status.idle();
      }
    },
    get lastResult() {
      return service.lastResult;
    },
    get treeRoots() {
      return tree.rootNodes;
    },
  };
}

export function deactivate(): void {}
