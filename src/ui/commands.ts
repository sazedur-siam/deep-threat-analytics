import { mkdir, readFile, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import * as vscode from 'vscode';
import {
  addAllowlistedPackage,
  addIgnore,
  addAllowlistedRule,
  CONFIG_DIR,
  defaultConfigTemplate,
} from '../config/projectConfig';
import type { Finding } from '../core/types';
import { toRange, type FindingRef } from './diagnostics';
import { summarizeScan, type TreeNode } from './model';
import { ADAPTERS, currentSettings, type ScanService } from './scanService';
import type { ScanResult } from '../core/engine';
import type { FindingsTree } from './treeView';

const EXAMPLE_RULES = `# Custom Deep Threat Analytics rules. Same format as the built-in rules.
# A rule with the same id as a built-in rule replaces it; "enabled: false" turns it off.
#
# - id: custom/unapproved-host
#   title: Talks to an unapproved host
#   category: network        # network | exfiltration | exec | secrets-fs | env-access | obfuscation | ...
#   severity: high           # info | low | medium | high | critical
#   languages: [javascript, typescript, python]
#   match:
#     any:
#       - regex: 'https?://[a-z0-9.-]*\\.example\\.invalid'
#     scope: line            # line | file | package
#   message: '{package} contacts an unapproved host in {file}'
[]
`;

/** Folder whose .depthreat/config.yaml should receive an edit for the given file. */
export function configFolder(fileHint?: string): string | undefined {
  if (fileHint) {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(fileHint));
    return folder ? folder.uri.fsPath : path.dirname(fileHint);
  }
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

async function readOrTemplate(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return defaultConfigTemplate();
  }
}

/** Apply a text edit to `<folder>/.depthreat/config.yaml`, creating it from the template. */
export async function editProjectConfig(
  folder: string,
  edit: (text: string) => string,
): Promise<string> {
  const file = path.join(folder, CONFIG_DIR, 'config.yaml');
  const before = await readOrTemplate(file);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, edit(before));
  return file;
}

/** Commands accept either a quick-fix reference or a tree node. */
function refFrom(arg: FindingRef | TreeNode | undefined): FindingRef | undefined {
  if (!arg) return undefined;
  if ('kind' in arg) {
    if (arg.kind === 'finding') {
      const f = arg.finding;
      return {
        manifestPath: f.location?.file,
        ecosystem: f.package.ecosystem,
        name: f.package.name,
        ruleId: f.ruleId,
        findingId: f.id,
      };
    }
    if (arg.kind === 'package') {
      const [ecosystem, rest] = arg.packageKey.split(':') as [string, string];
      return { ecosystem, name: rest.slice(0, rest.lastIndexOf('@')) };
    }
    return undefined;
  }
  return arg;
}

export function registerCommands(
  service: ScanService,
  tree: FindingsTree,
  view: vscode.TreeView<TreeNode>,
): vscode.Disposable[] {
  const afterConfigEdit = async (file: string, what: string) => {
    if (!vscode.workspace.isTrusted) {
      void vscode.window.showWarningMessage(
        `DepThreat: ${what}. Note: .depthreat/config.yaml is ignored until you trust this workspace.`,
      );
    } else {
      void vscode.window.setStatusBarMessage(
        `DepThreat: ${what} (${vscode.workspace.asRelativePath(file)})`,
        4000,
      );
    }
    await service.rescan();
  };

  /** One notification per user-started scan, only when there is something to look at. */
  const announce = (result: ScanResult | undefined) => {
    if (!result) return result;
    const summary = summarizeScan(result, currentSettings().minSeverity);
    if (summary.count || summary.status !== 'pass') {
      void vscode.window
        .showWarningMessage(`DepThreat: ${summary.text}`, 'Show Findings')
        .then((choice) => choice && vscode.commands.executeCommand('depthreat.findings.focus'));
    }
    return result;
  };

  const reg = vscode.commands.registerCommand;
  return [
    reg('depthreat.scanWorkspace', async () => announce(await service.scan())),

    reg('depthreat.scanManifest', async (uri?: vscode.Uri, uris?: vscode.Uri[]) => {
      const targets = (uris?.length ? uris : [uri ?? vscode.window.activeTextEditor?.document.uri])
        .filter((u): u is vscode.Uri => u !== undefined)
        .filter((u) => ADAPTERS.some((a) => a.matches(u.fsPath)));
      if (!targets.length) {
        void vscode.window.showInformationMessage(
          'DepThreat: open or select a dependency manifest (package.json, pyproject.toml, requirements*.txt, go.mod, Cargo.toml) to scan.',
        );
        return undefined;
      }
      return announce(await service.scan(targets));
    }),

    reg('depthreat.clearCache', async () => {
      service.cache.clear();
      await service.cache.save();
      void vscode.window.setStatusBarMessage('DepThreat: scan cache cleared', 3000);
    }),

    reg('depthreat.openFinding', async (f?: Finding) => {
      if (!f?.location) return;
      await vscode.window.showTextDocument(vscode.Uri.file(f.location.file), {
        selection: toRange(f.location.range),
        preview: true,
      });
    }),

    reg('depthreat.revealPackage', async (name?: string) => {
      await vscode.commands.executeCommand('depthreat.findings.focus');
      const node = name ? tree.findPackage(name) : undefined;
      if (node) await view.reveal(node, { select: true, focus: true, expand: true });
    }),

    reg('depthreat.ignoreRule', async (arg?: FindingRef | TreeNode) => {
      const ref = refFrom(arg);
      const folder = configFolder(ref?.manifestPath);
      if (!ref?.ruleId || !folder) return;
      const pkg = ref.ecosystem === 'npm' ? ref.name : `${ref.ecosystem}:${ref.name}`;
      const file = await editProjectConfig(folder, (t) =>
        addIgnore(t, { package: pkg, rule: ref.ruleId!, reason: 'ignored from VS Code' }),
      );
      await afterConfigEdit(file, `ignored ${ref.ruleId} for ${ref.name}`);
    }),

    reg('depthreat.ignoreFinding', async (arg?: FindingRef | TreeNode) => {
      const ref = refFrom(arg);
      const folder = configFolder(ref?.manifestPath);
      if (!ref?.findingId || !folder) return;
      const file = await editProjectConfig(folder, (t) =>
        addIgnore(t, { finding: ref.findingId!, reason: `${ref.ruleId} in ${ref.name}` }),
      );
      await afterConfigEdit(file, `ignored this ${ref.ruleId} finding in ${ref.name}`);
    }),

    reg('depthreat.allowlistPackage', async (arg?: FindingRef | TreeNode) => {
      const ref = refFrom(arg);
      const folder = configFolder(ref?.manifestPath);
      if (!ref || !folder) return;
      const pattern = ref.ecosystem === 'npm' ? ref.name : `${ref.ecosystem}:${ref.name}`;
      const file = await editProjectConfig(folder, (t) => addAllowlistedPackage(t, pattern));
      await afterConfigEdit(file, `allowlisted ${ref.name}`);
    }),

    reg('depthreat.allowlistRule', async (arg?: FindingRef | TreeNode) => {
      const ref = refFrom(arg);
      const folder = configFolder(ref?.manifestPath);
      if (!ref?.ruleId || !folder) return;
      const file = await editProjectConfig(folder, (t) => addAllowlistedRule(t, ref.ruleId!));
      await afterConfigEdit(file, `turned off ${ref.ruleId} everywhere`);
    }),

    reg('depthreat.createConfig', async () => {
      const folder = configFolder();
      if (!folder) return;
      const file = await editProjectConfig(folder, (t) => t);
      await vscode.window.showTextDocument(vscode.Uri.file(file));
    }),

    reg('depthreat.openRulesFolder', async () => {
      const folder = configFolder();
      if (!folder) return;
      const file = path.join(folder, CONFIG_DIR, 'rules', 'custom.yaml');
      await mkdir(path.dirname(file), { recursive: true });
      try {
        await writeFile(file, EXAMPLE_RULES, { flag: 'wx' });
      } catch {
        // keep the user's existing file
      }
      await vscode.window.showTextDocument(vscode.Uri.file(file));
    }),

    reg('depthreat.exportFindings', async () => {
      const result = service.lastResult;
      if (!result) {
        void vscode.window.showInformationMessage(
          'DepThreat: run a scan before exporting findings.',
        );
        return;
      }
      const target = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(configFolder() ?? '', 'depthreat-findings.json')),
        filters: { JSON: ['json'] },
      });
      if (!target) return;
      const report = {
        tool: 'deep-threat-analytics',
        generatedAt: new Date().toISOString(),
        status: result.status,
        stats: result.stats,
        manifests: result.manifests.map((m) => ({
          path: m.manifestPath,
          ecosystem: m.ecosystem,
          dependencies: m.deps.length,
          ...(m.error ? { error: m.error } : {}),
        })),
        violations: result.violations,
        findings: result.findings,
      };
      await writeFile(target.fsPath, `${JSON.stringify(report, null, 2)}\n`);
      void vscode.window.setStatusBarMessage(
        `DepThreat: exported ${result.findings.length} findings`,
        4000,
      );
    }),
  ];
}
