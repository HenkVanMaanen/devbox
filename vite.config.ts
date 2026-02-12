import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { parse } from 'marked';

const __dirname = dirname(fileURLToPath(import.meta.url));

function markdownHtml(): Plugin {
  return {
    name: 'markdown-html',
    async transform(code: string, id: string) {
      if (!id.endsWith('.md?html')) return null;
      const html = await parse(code);
      return { code: `export default ${JSON.stringify(html)};`, map: null };
    },
  };
}

export default defineConfig({
  plugins: [markdownHtml(), svelte(), tailwindcss()],
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
    allowedHosts: ['3000.310d39ae.dev.calabytes.nl'],
  },
});
