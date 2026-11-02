import * as vscode from 'vscode';
import type { Finding, Severity } from '../core/types';
import type { ScanSummary, TreeNode } from './model';

function severityIcon(severity: Severity): vscode.ThemeIcon {
  if (severity === 'critical' || severity === 'high') {
    return new vscode.ThemeIcon('error', new vscode.ThemeColor('list.errorForeground'));
  }
  if (severity === 'medium') {
    return new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground'));
  }
  return new vscode.ThemeIcon('info');
}

function findingTooltip(f: Finding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${f.title}** — ${f.severity}\n\n${f.message}\n\n`);
  md.appendMarkdown(`Rule \`${f.ruleId}\` · ${f.package.name}@${f.package.version}`);
  if (f.evidence) md.appendCodeblock(f.evidence);
  if (f.fixedVersion) md.appendMarkdown(`\n\nFixed in ${f.fixedVersion}`);
  for (const ref of f.references ?? []) md.appendMarkdown(`\n\n[${ref}](${ref})`);
  return md;
}

export class FindingsTree implements vscode.TreeDataProvider<TreeNode> {
  private roots: TreeNode[] = [];
  private parents = new Map<TreeNode, TreeNode>();
  private readonly emitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;

  update(roots: TreeNode[]): void {
    this.roots = roots;
    this.parents.clear();
    const walk = (node: TreeNode) => {
      for (const child of node.children) {
        this.parents.set(child, node);
        walk(child);
      }
    };
    roots.forEach(walk);
    this.emitter.fire(undefined);
  }

  get rootNodes(): readonly TreeNode[] {
    return this.roots;
  }

  /** First package node whose name matches (used by "Show in sidebar"). */
  findPackage(name: string): TreeNode | undefined {
    for (const root of this.roots) {
      for (const node of root.children) {
        if (node.kind === 'package' && node.label.startsWith(`${name}@`)) return node;
      }
    }
    return undefined;
  }

  getChildren(node?: TreeNode): TreeNode[] {
    return node ? node.children : this.roots;
  }

  getParent(node: TreeNode): TreeNode | undefined {
    return this.parents.get(node);
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    const { Expanded, Collapsed, None } = vscode.TreeItemCollapsibleState;
    switch (node.kind) {
      case 'violations': {
        const item = new vscode.TreeItem(node.label, Expanded);
        item.iconPath = new vscode.ThemeIcon(
          'shield',
          new vscode.ThemeColor('list.errorForeground'),
        );
        item.contextValue = 'violations';
        return item;
      }
      case 'manifest': {
        const item = new vscode.TreeItem(node.label, Expanded);
        item.resourceUri = vscode.Uri.file(node.manifestPath);
        item.iconPath = vscode.ThemeIcon.File;
        item.tooltip = node.manifestPath;
        item.contextValue = 'manifest';
        item.command = { title: 'Open', command: 'vscode.open', arguments: [item.resourceUri] };
        return item;
      }
      case 'package': {
        const item = new vscode.TreeItem(node.label, Collapsed);
        item.description = node.description;
        item.iconPath = severityIcon(node.severity);
        item.contextValue = 'package';
        return item;
      }
      case 'finding': {
        const f = node.finding;
        const item = new vscode.TreeItem(node.label, None);
        item.description = node.description;
        item.iconPath = severityIcon(f.severity);
        item.tooltip = findingTooltip(f);
        item.contextValue = 'finding';
        if (f.location)
          item.command = { title: 'Open', command: 'depthreat.openFinding', arguments: [f] };
        return item;
      }
    }
  }
}

export class StatusBar implements vscode.Disposable {
  private readonly item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);

  constructor() {
    this.item.name = 'Deep Threat Analytics';
    this.item.command = 'workbench.view.extension.depthreat';
    this.idle();
  }

  dispose(): void {
    this.item.dispose();
  }

  idle(): void {
    this.item.text = '$(shield) DepThreat';
    this.item.tooltip =
      'Deep Threat Analytics: run "DepThreat: Scan Workspace" to analyze dependencies';
    this.item.backgroundColor = undefined;
    this.item.show();
  }

  scanning(): void {
    this.item.text = '$(sync~spin) DepThreat';
    this.item.tooltip = 'Scanning dependencies…';
  }

  show(summary: ScanSummary): void {
    const icon = summary.status === 'fail' ? '$(error)' : summary.count ? '$(warning)' : '$(pass)';
    this.item.text = `${icon} DepThreat${summary.count ? ` ${summary.count}` : ''}`;
    this.item.tooltip = `Deep Threat Analytics: ${summary.text}`;
    this.item.backgroundColor =
      summary.status === 'fail'
        ? new vscode.ThemeColor('statusBarItem.errorBackground')
        : summary.status === 'warn'
          ? new vscode.ThemeColor('statusBarItem.warningBackground')
          : undefined;
  }
}
