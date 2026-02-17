import { svelte } from '@sveltejs/vite-plugin-svelte';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [svelte({ hot: false })],
  resolve: {
    alias: {
      $components: resolve(__dirname, './src/components'),
      $lib: resolve(__dirname, './src/lib'),
      $pages: resolve(__dirname, './src/pages'),
    },
    conditions: ['browser'],
  },
  test: {
    coverage: {
      exclude: ['src/lib/data/**'],
      include: ['src/lib/**/*.ts'],
      provider: 'v8',
      thresholds: {
        branches: 85,
        functions: 90,
        lines: 90,
      },
    },
    environment: 'happy-dom',
    include: ['tests/vitest/**/*.test.ts'],
    restoreMocks: true,
  },
});
