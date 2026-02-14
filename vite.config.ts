import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { parse } from 'marked';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

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
  build: {
    outDir: 'dist',
  },
  define: {
    __APP_VERSION__: JSON.stringify(process.env['APP_VERSION'] ?? 'dev'),
  },
  plugins: [markdownHtml(), svelte(), tailwindcss()],
  resolve: {
    alias: {
      $components: resolve(__dirname, './src/components'),
      $lib: resolve(__dirname, './src/lib'),
      $pages: resolve(__dirname, './src/pages'),
    },
  },
  server: {
    allowedHosts: true,
    host: '0.0.0.0',
    port: 8080,
  },
});
