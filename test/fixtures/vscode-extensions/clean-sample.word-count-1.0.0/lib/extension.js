// TEST FIXTURE: a harmless extension. Never executed.
const vscode = require('vscode');

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('wordCount.show', () => {
      const text = vscode.window.activeTextEditor?.document.getText() ?? '';
      const words = text.split(/\s+/).filter(Boolean).length;
      vscode.window.showInformationMessage(`${words} words`);
    }),
  );
}

module.exports = { activate };
