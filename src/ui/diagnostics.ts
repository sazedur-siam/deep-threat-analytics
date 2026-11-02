import * as vscode from 'vscode';
import type { DepThreatSettings, DiagnosticLevel } from '../config/settings';
import type { ScanResult } from '../core/engine';
import type { SourceRange } from '../core/types';
import { compareVersions } from '../scanners/osv';
import {
  anchorHover,
  anchorLevel,
  anchorMessage,
  buildAnchors,
  fixedVersionEdit,
  type DepAnchor,
} from './model';

export const DIAGNOSTIC_SOURCE = 'DepThreat';

const LEVELS: Record<DiagnosticLevel, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

export function toRange(r: SourceRange): vscode.Range {
  return new vscode.Range(r.startLine, r.startCol, r.endLine, r.endCol);
}

/** Publishes one diagnostic per affected dependency line and remembers the anchors behind them. */
export class DiagnosticsPresenter implements vscode.Disposable {
  readonly collection = vscode.languages.createDiagnosticCollection('depthreat');
  private anchors = new Map<string, DepAnchor[]>();

  dispose(): void {
    this.collection.dispose();
  }

  update(result: ScanResult, settings: DepThreatSettings): void {
    this.collection.clear();
    this.anchors.clear();
    for (const anchor of buildAnchors(result, settings.minSeverity)) {
      const key = vscode.Uri.file(anchor.manifestPath).toString();
      this.anchors.set(key, [...(this.anchors.get(key) ?? []), anchor]);
    }
    for (const [key, anchors] of this.anchors) {
      const diagnostics = anchors.map((a) => {
        const d = new vscode.Diagnostic(
          toRange(a.dep.range),
          anchorMessage(a),
          LEVELS[anchorLevel(a, settings.severityMapping)],
        );
        d.source = DIAGNOSTIC_SOURCE;
        d.code = a.findings[0]?.ruleId;
        return d;
      });
      this.collection.set(vscode.Uri.parse(key), diagnostics);
    }
  }

  anchorsFor(uri: vscode.Uri): DepAnchor[] {
    return this.anchors.get(uri.toString()) ?? [];
  }

  anchorAt(uri: vscode.Uri, range: vscode.Range | vscode.Position): DepAnchor | undefined {
    return this.anchorsFor(uri).find((a) =>
      toRange(a.dep.range).intersection(
        range instanceof vscode.Position ? new vscode.Range(range, range) : range,
      ),
    );
  }

  clear(): void {
    this.collection.clear();
    this.anchors.clear();
  }
}

export const MANIFEST_SELECTOR: vscode.DocumentSelector = [
  { scheme: 'file', pattern: '**/package.json' },
  { scheme: 'file', pattern: '**/pyproject.toml' },
  { scheme: 'file', pattern: '**/requirements*.txt' },
  { scheme: 'file', pattern: '**/go.mod' },
  { scheme: 'file', pattern: '**/Cargo.toml' },
];

export function registerHover(presenter: DiagnosticsPresenter): vscode.Disposable {
  return vscode.languages.registerHoverProvider(MANIFEST_SELECTOR, {
    provideHover(doc, position) {
      const anchor = presenter.anchorAt(doc.uri, position);
      if (!anchor) return undefined;
      const md = new vscode.MarkdownString(anchorHover(anchor));
      md.appendMarkdown(
        `\n\n[Show in sidebar](command:depthreat.revealPackage?${encodeURIComponent(
          JSON.stringify([anchor.dep.name]),
        )})`,
      );
      md.isTrusted = { enabledCommands: ['depthreat.revealPackage'] };
      return new vscode.Hover(md, toRange(anchor.dep.range));
    },
  });
}

export interface FindingRef {
  manifestPath?: string;
  ecosystem: string;
  name: string;
  ruleId?: string;
  findingId?: string;
}

export function registerCodeActions(presenter: DiagnosticsPresenter): vscode.Disposable {
  return vscode.languages.registerCodeActionsProvider(
    MANIFEST_SELECTOR,
    {
      provideCodeActions(doc, range) {
        const anchor = presenter.anchorAt(doc.uri, range);
        if (!anchor) return [];
        const actions: vscode.CodeAction[] = [];
        const add = (title: string, command: string, args: unknown[], preferred = false) => {
          const a = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
          a.command = { title, command, arguments: args };
          a.isPreferred = preferred;
          actions.push(a);
        };
        const [top] = anchor.findings;
        // Bump the dependency itself to the highest version that fixes all its known issues.
        const fixed = anchor.findings
          .filter((f) => f.fixedVersion && f.package.name === anchor.dep.name)
          .map((f) => f.fixedVersion as string)
          .sort(compareVersions)
          .at(-1);
        if (fixed) {
          const lineNo = anchor.dep.range.startLine;
          const edit = fixedVersionEdit(doc.lineAt(lineNo).text, anchor.dep, fixed, doc.uri.fsPath);
          if (edit) {
            const fix = new vscode.CodeAction(
              `Update ${anchor.dep.name} to ${fixed} (fixes known vulnerabilities)`,
              vscode.CodeActionKind.QuickFix,
            );
            fix.edit = new vscode.WorkspaceEdit();
            fix.edit.replace(
              doc.uri,
              new vscode.Range(lineNo, edit.startCol, lineNo, edit.endCol),
              edit.newText,
            );
            fix.isPreferred = true;
            actions.push(fix);
          }
        }
        add(
          `Show ${anchor.findings.length} finding(s) for ${anchor.dep.name}`,
          'depthreat.revealPackage',
          [anchor.dep.name],
          true,
        );
        if (top?.location) {
          const line = top.location.range.startLine + 1;
          add(
            `Open ${top.package.name} code (${vscode.workspace.asRelativePath(top.location.file)}:${line})`,
            'depthreat.openFinding',
            [top],
          );
        }
        for (const ruleId of [...new Set(anchor.findings.map((f) => f.ruleId))].slice(0, 3)) {
          const pkg = anchor.findings.find((f) => f.ruleId === ruleId)!.package;
          const ref: FindingRef = {
            manifestPath: anchor.manifestPath,
            ecosystem: pkg.ecosystem,
            name: pkg.name,
            ruleId,
          };
          add(`Ignore ${ruleId} for ${pkg.name}`, 'depthreat.ignoreRule', [ref]);
        }
        const ref: FindingRef = {
          manifestPath: anchor.manifestPath,
          ecosystem: anchor.dep.ecosystem,
          name: anchor.dep.name,
        };
        add(`Allowlist ${anchor.dep.name} (trust this package)`, 'depthreat.allowlistPackage', [
          ref,
        ]);
        return actions;
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  );
}
