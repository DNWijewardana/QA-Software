import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@qa/core': r('./packages/core/src/index.ts'),
      '@qa/contracts': r('./packages/contracts/src/index.ts'),
      '@qa/engines': r('./packages/engines/src/index.ts'),
      '@qa/orchestrator': r('./packages/orchestrator/src/index.ts'),
      '@qa/reporters': r('./packages/reporters/src/index.ts'),
      '@qa/jobs/adapters': r('./packages/jobs/src/adapters/index.ts'),
      '@qa/jobs': r('./packages/jobs/src/index.ts'),
    },
  },
  test: {
    include: ['tests/**/*.test.ts', 'packages/**/*.test.ts'],
    environment: 'node',
  },
});
