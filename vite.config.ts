import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  resolve: {
    alias: {
      $lib: resolve(__dirname, './src/lib'),
      $components: resolve(__dirname, './src/components'),
      $pages: resolve(__dirname, './src/pages'),
    },
  },
  define: {
    __APP_VERSION__: JSON.stringify(process.env['APP_VERSION'] ?? 'dev'),
  },
  build: {
    outDir: 'dist',
  },
  server: {
    port: 8080,
    host: '0.0.0.0',
  },
});
