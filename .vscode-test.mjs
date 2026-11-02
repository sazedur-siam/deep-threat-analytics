import { defineConfig } from '@vscode/test-cli';

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  version: '1.90.0',
  mocha: { ui: 'tdd', timeout: 60000 },
});
