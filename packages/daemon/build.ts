import { buildSync } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Bundle and minify the daemon source
const result = buildSync({
  entryPoints: [join(__dirname, 'src/daemon.ts')],
  bundle: true,
  minify: true,
  platform: 'node',
  target: 'node18',
  format: 'cjs',
  write: false,
});

const bundled = result.outputFiles[0]!.text;
const script = '#!/usr/bin/env node\n' + bundled;

// Write as a TS module exporting the template string
const distDir = join(__dirname, 'dist');
mkdirSync(distDir, { recursive: true });

const escaped = script.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
writeFileSync(join(distDir, 'template.ts'), `export const daemonTemplate = \`${escaped}\`;\n`);

console.log(`daemon: bundled (${script.length} bytes)`);
