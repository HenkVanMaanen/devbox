import * as esbuild from 'esbuild';
import postcss from 'postcss';
import tailwindcss from '@tailwindcss/postcss';
import { readFile, writeFile } from 'node:fs/promises';

const tailwindPlugin = {
    name: 'tailwindcss',
    setup(build) {
        build.onLoad({ filter: /\.css$/ }, async (args) => {
            const source = await readFile(args.path, 'utf8');
            const result = await postcss([tailwindcss()]).process(source, { from: args.path });
            return { contents: result.css, loader: 'css', watchDirs: ['web'] };
        });
    },
};

const entryPoints = ['web/js/app.js', 'web/src/style.css'];

if (process.argv[2] === 'build') {
    const result = await esbuild.build({
        entryPoints,
        bundle: true,
        minify: true,
        format: 'esm',
        outdir: 'dist',
        outbase: 'web',
        entryNames: '[dir]/[name]-[hash]',
        plugins: [tailwindPlugin],
        metafile: true,
    });

    // Generate dist/index.html from source template
    const outputs = Object.keys(result.metafile.outputs);
    const js = outputs.find(f => f.endsWith('.js')).replace('dist/', '');
    const css = outputs.find(f => f.endsWith('.css')).replace('dist/', '');
    let html = await readFile('web/index.html', 'utf8');
    html = html.replace('href="src/style.css"', `href="${css}"`);
    html = html.replace('src="js/app.js"', `src="${js}"`);
    await writeFile('dist/index.html', html);
} else {
    const ctx = await esbuild.context({
        entryPoints,
        bundle: true,
        format: 'esm',
        outdir: 'web',
        outbase: 'web',
        write: false,
        sourcemap: true,
        plugins: [tailwindPlugin],
        banner: {
            js: `new EventSource('/esbuild').addEventListener('change', () => location.reload());`,
        },
    });
    await ctx.watch();
    await ctx.serve({ servedir: 'web', host: '0.0.0.0', port: 3000 });
    console.log('Dev server: http://localhost:3000');
    process.on('SIGINT', () => { ctx.dispose(); process.exit(); });
    process.on('SIGTERM', () => { ctx.dispose(); process.exit(); });
}
