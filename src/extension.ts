import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('depthreat.scanWorkspace', () => {
      void vscode.window.showInformationMessage('DepThreat: scanning is not implemented yet.');
    }),
  );
}

export function deactivate(): void {}
