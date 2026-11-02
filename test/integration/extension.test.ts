import * as assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';
import type { DepThreatApi } from '../../src/extension';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function api(): Promise<DepThreatApi> {
  const ext = vscode.extensions.getExtension<DepThreatApi>('MdSazedurRahman.deep-threat-analytics');
  assert.ok(ext, 'extension not found');
  return ext.activate();
}

function workspaceRoot(): string {
  const folder = vscode.workspace.workspaceFolders?.[0];
  assert.ok(folder, 'no workspace folder');
  return folder.uri.fsPath;
}

function manifestUri(): vscode.Uri {
  return vscode.Uri.file(path.join(workspaceRoot(), 'package.json'));
}

function ourDiagnostics(): vscode.Diagnostic[] {
  return vscode.languages.getDiagnostics(manifestUri()).filter((d) => d.source === 'DepThreat');
}

function lineOf(name: string): number {
  return readFileSync(manifestUri().fsPath, 'utf8')
    .split('\n')
    .findIndex((l) => l.includes(`"${name}"`));
}

suite('Deep Threat Analytics', () => {
  test('registers its commands', async () => {
    await api();
    const commands = await vscode.commands.getCommands(true);
    for (const c of [
      'scanWorkspace',
      'scanManifest',
      'ignoreRule',
      'allowlistPackage',
      'exportFindings',
    ]) {
      assert.ok(commands.includes(`depthreat.${c}`), c);
    }
  });

  test('scans the workspace and reports diagnostics on dependency lines', async () => {
    const result = await (await api()).scan();
    assert.ok(result, 'scan returned nothing');
    assert.ok(result.findings.some((f) => f.ruleId === 'exfiltration/env-to-network'));
    const diags = ourDiagnostics();
    const stealer = diags.find((d) => d.range.start.line === lineOf('evil-env-stealer'));
    assert.ok(stealer, 'no diagnostic on evil-env-stealer');
    assert.strictEqual(stealer.severity, vscode.DiagnosticSeverity.Error);
    assert.match(stealer.message, /Sends environment variables over the network/);
    const hook = diags.find((d) => d.range.start.line === lineOf('evil-postinstall'));
    assert.ok(hook, 'no diagnostic on evil-postinstall');
    assert.ok(!diags.some((d) => d.range.start.line === lineOf('clean-utils')));
  });

  test('fills the findings tree', async () => {
    const roots = (await api()).treeRoots;
    const manifest = roots.find((n) => n.kind === 'manifest');
    assert.ok(manifest, 'no manifest node');
    const labels = manifest.children.map((c) => c.label);
    assert.deepStrictEqual(labels, ['evil-env-stealer@1.0.0', 'evil-postinstall@2.1.0']);
  });

  test('shows a hover on flagged dependencies', async () => {
    const doc = await vscode.workspace.openTextDocument(manifestUri());
    const position = new vscode.Position(lineOf('evil-env-stealer'), 6);
    const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
      'vscode.executeHoverProvider',
      doc.uri,
      position,
    );
    const text = hovers
      .flatMap((h) => h.contents)
      .map((c) => (typeof c === 'string' ? c : 'value' in c ? c.value : ''))
      .join('\n');
    assert.match(text, /Deep Threat Analytics/);
  });

  test('offers quick fixes on flagged dependencies', async () => {
    const doc = await vscode.workspace.openTextDocument(manifestUri());
    const position = new vscode.Position(lineOf('evil-env-stealer'), 6);
    const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
      'vscode.executeCodeActionProvider',
      doc.uri,
      new vscode.Range(position, position),
    );
    const titles = actions.map((a) => a.title);
    assert.ok(
      titles.some((t) => t.startsWith('Ignore exfiltration/env-to-network for evil-env-stealer')),
      titles.join('\n'),
    );
    assert.ok(titles.includes('Allowlist evil-env-stealer (trust this package)'));
  });

  test('ignoring a rule writes the project config and hides the finding', async () => {
    await vscode.commands.executeCommand('depthreat.ignoreRule', {
      manifestPath: manifestUri().fsPath,
      ecosystem: 'npm',
      name: 'evil-env-stealer',
      ruleId: 'exfiltration/env-to-network',
    });
    const config = path.join(workspaceRoot(), '.depthreat', 'config.yaml');
    assert.ok(existsSync(config));
    assert.match(
      readFileSync(config, 'utf8'),
      /package: evil-env-stealer, rule: exfiltration\/env-to-network/,
    );
    const finding = (await api()).lastResult?.findings.find(
      (f) => f.ruleId === 'exfiltration/env-to-network',
    );
    assert.ok(finding?.suppressed, 'finding should be suppressed after rescan');
  });

  test('allowlisting a package removes its diagnostics', async () => {
    await vscode.commands.executeCommand('depthreat.allowlistPackage', {
      manifestPath: manifestUri().fsPath,
      ecosystem: 'npm',
      name: 'evil-postinstall',
    });
    await sleep(50);
    assert.ok(!ourDiagnostics().some((d) => d.range.start.line === lineOf('evil-postinstall')));
  });

  test('scanning a non-manifest file does nothing', async () => {
    const other = vscode.Uri.file(path.join(workspaceRoot(), 'package-lock.json'));
    const result = await vscode.commands.executeCommand('depthreat.scanManifest', other);
    assert.strictEqual(result, undefined);
  });
});
