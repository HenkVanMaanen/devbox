import { buildSync, transformSync } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Bundle and minify the client-side JS
const jsResult = buildSync({
  entryPoints: [join(__dirname, 'src/script.ts')],
  bundle: true,
  minify: true,
  platform: 'browser',
  target: 'es2020',
  format: 'iife',
  write: false,
});
const js = jsResult.outputFiles[0]!.text.trim();

// Minify the CSS
const cssRaw = readFileSync(join(__dirname, 'src/style.css'), 'utf8');
const cssResult = transformSync(cssRaw, {
  loader: 'css',
  minify: true,
});
const css = cssResult.code.trim();

// Read the HTML template and inline CSS + JS
let html = readFileSync(join(__dirname, 'src/index.html'), 'utf8');
html = html.replace('__CSS__', css);
html = html.replace('__JS__', js);

// Minify HTML: collapse whitespace between tags
html = html.replace(/>\s+</g, '><').trim();

// Write as a TS module exporting the template string
const distDir = join(__dirname, 'dist');
mkdirSync(distDir, { recursive: true });

const escaped = html.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
writeFileSync(join(distDir, 'template.ts'), `export const overviewTemplate = \`${escaped}\`;\n`);

console.log(`overview: bundled (${html.length} bytes)`);
