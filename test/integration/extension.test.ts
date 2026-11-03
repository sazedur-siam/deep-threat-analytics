import * as assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';
import type { ScanResult } from '../../src/core/engine';
import type { DepThreatApi } from '../../src/extension';
import { makeExtensionsDir } from '../helpers/vscodeExtensions';

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

suite('DepThreat Analytics', () => {
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
    // Worst first: evil-postinstall pipes a download into a shell (critical).
    assert.deepStrictEqual(labels, ['evil-postinstall@2.1.0', 'evil-env-stealer@1.0.0']);
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
    assert.match(text, /DepThreat Analytics/);
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

  test('exports a Markdown report on demand', async () => {
    const target = vscode.Uri.file(path.join(workspaceRoot(), 'out', 'report.md'));
    const file = await vscode.commands.executeCommand<string>('depthreat.exportReport', target);
    assert.strictEqual(file, target.fsPath);
    const md = readFileSync(target.fsPath, 'utf8');
    assert.match(md, /^# DepThreat Analytics report/);
    assert.match(md, /## Findings by package/);
  });

  test('writes .depthreat/report.md after each scan when enabled', async () => {
    const config = vscode.workspace.getConfiguration('depthreat');
    await config.update('report.autoWrite', true, vscode.ConfigurationTarget.Workspace);
    try {
      const report = path.join(workspaceRoot(), '.depthreat', 'report.md');
      await (await api()).scan();
      for (let i = 0; i < 50 && !existsSync(report); i++) await sleep(20);
      assert.ok(existsSync(report), 'report.md was not written');
      assert.match(readFileSync(report, 'utf8'), /# DepThreat Analytics report/);
    } finally {
      await config.update('report.autoWrite', undefined, vscode.ConfigurationTarget.Workspace);
    }
  });

  test('scanning a non-manifest file does nothing', async () => {
    const other = vscode.Uri.file(path.join(workspaceRoot(), 'package-lock.json'));
    const result = await vscode.commands.executeCommand('depthreat.scanManifest', other);
    assert.strictEqual(result, undefined);
  });
});

suite('Installed extensions', () => {
  let dir: string;
  const manifest = () => vscode.Uri.file(path.join(dir, 'extensions.json'));
  const idLine = (id: string) =>
    readFileSync(manifest().fsPath, 'utf8')
      .split('\n')
      .findIndex((l) => l.includes(`"${id}"`));

  suiteSetup(async () => {
    const ext = vscode.extensions.getExtension('MdSazedurRahman.deep-threat-analytics');
    assert.ok(ext, 'extension not found');
    // A copy under a `.vscode/extensions` folder, like the real one in the home directory.
    dir = await makeExtensionsDir(
      path.join(ext.extensionPath, 'test', 'fixtures', 'vscode-extensions'),
      '.vscode',
    );
  });

  test('registers the command', async () => {
    await api();
    assert.ok((await vscode.commands.getCommands(true)).includes('depthreat.scanExtensions'));
  });

  test('scans the given extensions folders', async () => {
    const result = await vscode.commands.executeCommand<ScanResult | undefined>(
      'depthreat.scanExtensions',
      [dir, dir],
    );
    assert.ok(result, 'scan returned nothing');
    assert.deepStrictEqual(
      result.manifests.map((m) => m.manifestPath),
      [manifest().fsPath],
    );
    const flagged = new Set(
      result.findings.filter((f) => !f.suppressed).map((f) => f.package.name),
    );
    for (const id of [
      'glassworm-sample.color-theme-glow',
      'devtools-sample.ssh-helper',
      'esbenp.prettier-vscod',
    ]) {
      assert.ok(flagged.has(id), id);
    }
    assert.ok(!flagged.has('clean-sample.word-count'));
    assert.ok(!flagged.has('mdsazedurrahman.deep-threat-analytics'));
    assert.ok(
      result.findings.some((f) => f.ruleId === 'obfuscation/invisible-unicode-payload'),
      'no GlassWorm finding',
    );
    assert.ok(result.findings.some((f) => f.ruleId === 'install-hook/vscode-uninstall-script'));
  });

  test('labels the tree root by editor', async () => {
    const roots = (await api()).treeRoots.filter((n) => n.kind === 'manifest');
    assert.strictEqual(roots.length, 1);
    const [root] = roots;
    assert.match(root!.label, /^Installed extensions — VS Code \(.*\.vscode[/\\]extensions\)$/);
    assert.ok(root!.children.some((c) => c.label === 'devtools-sample.ssh-helper@0.2.0'));
  });

  test('puts diagnostics and hovers on extension ids in extensions.json', async () => {
    const diags = vscode.languages
      .getDiagnostics(manifest())
      .filter((d) => d.source === 'DepThreat');
    const line = idLine('devtools-sample.ssh-helper');
    const stealer = diags.find((d) => d.range.start.line === line);
    assert.ok(stealer, 'no diagnostic on the credential stealer');
    assert.strictEqual(stealer.severity, vscode.DiagnosticSeverity.Error);
    assert.ok(!diags.some((d) => d.range.start.line === idLine('Clean-Sample.word-count')));

    const doc = await vscode.workspace.openTextDocument(manifest());
    const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
      'vscode.executeHoverProvider',
      doc.uri,
      new vscode.Position(line, stealer.range.start.character + 2),
    );
    const text = hovers
      .flatMap((h) => h.contents)
      .map((c) => (typeof c === 'string' ? c : 'value' in c ? c.value : ''))
      .join('\n');
    assert.match(text, /devtools-sample\.ssh-helper/);
  });

  test('ignoring an extension finding writes the workspace config, not the extensions folder', async () => {
    await vscode.commands.executeCommand('depthreat.ignoreRule', {
      manifestPath: manifest().fsPath,
      ecosystem: 'vscode',
      name: 'devtools-sample.ssh-helper',
      ruleId: 'install-hook/vscode-startup-activation',
    });
    assert.ok(!existsSync(path.join(dir, '.depthreat')));
    assert.match(
      readFileSync(path.join(workspaceRoot(), '.depthreat', 'config.yaml'), 'utf8'),
      /package: vscode:devtools-sample\.ssh-helper, rule: install-hook\/vscode-startup-activation/,
    );
    const finding = (await api()).lastResult?.findings.find(
      (f) => f.ruleId === 'install-hook/vscode-startup-activation',
    );
    assert.ok(finding?.suppressed, 'finding should be suppressed after rescan');
  });

  test('ignores folders without an extensions.json', async () => {
    const result = await vscode.commands.executeCommand('depthreat.scanExtensions', [
      path.join(dir, 'clean-sample.word-count-1.0.0'),
    ]);
    assert.strictEqual(result, undefined);
  });
});
