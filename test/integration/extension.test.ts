import * as assert from 'node:assert';
import * as vscode from 'vscode';

suite('extension', () => {
  test('activates and registers the scan command', async () => {
    const ext = vscode.extensions.getExtension('sazedur-siam.deep-threat-analytics');
    assert.ok(ext, 'extension not found');
    await ext.activate();
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.includes('depthreat.scanWorkspace'));
  });
});
