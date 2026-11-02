import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/extension.ts', 'src/ui/**'],
      thresholds: {
        'src/core/**': { lines: 80, functions: 80, branches: 80, statements: 80 },
        'src/scanners/**': { lines: 80, functions: 80, branches: 80, statements: 80 },
      },
    },
  },
});
