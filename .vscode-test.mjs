import { defineConfig } from '@vscode/test-cli';
import { cpSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Tests edit .depthreat/config.yaml, so they run against a throwaway copy of the fixture.
const workspace = mkdtempSync(join(tmpdir(), 'depthreat-it-'));
cpSync('test/fixtures/npm-sample', workspace, { recursive: true });

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  version: '1.90.0',
  workspaceFolder: workspace,
  launchArgs: ['--disable-extensions', '--disable-workspace-trust'],
  mocha: { ui: 'tdd', timeout: 60000 },
});
