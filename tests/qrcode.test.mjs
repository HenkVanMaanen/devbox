import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mock minimal DOM for SVG generation
globalThis.document = {
    createElementNS: (ns, tag) => {
        const attrs = {};
        const children = [];
        return {
            setAttribute: (k, v) => { attrs[k] = v; },
            appendChild: (child) => { children.push(child); },
            get outerHTML() {
                const attrStr = Object.entries(attrs).map(([k, v]) => `${k}="${v}"`).join(' ');
                const childStr = children.map(c => c.outerHTML || '').join('');
                return `<${tag} ${attrStr}>${childStr}</${tag}>`;
            }
        };
    }
};

const { generateQR } = await import('../web/js/qrcode.js');

describe('qrcode.js', () => {
    describe('generateQR', () => {
        it('returns an SVG string', () => {
            const svg = generateQR('hello');
            assert.ok(svg.startsWith('<svg '));
            assert.ok(svg.endsWith('</svg>'));
        });

        it('contains path elements', () => {
            const svg = generateQR('test');
            assert.ok(svg.includes('<path '));
        });

        it('sets viewBox attribute', () => {
            const svg = generateQR('hello');
            assert.ok(svg.includes('viewBox='));
        });

        it('sets width and height to 256', () => {
            const svg = generateQR('hello');
            assert.ok(svg.includes('width="256"'));
            assert.ok(svg.includes('height="256"'));
        });

        it('handles URLs', () => {
            const svg = generateQR('https://example.com/path?q=1&r=2');
            assert.ok(svg.startsWith('<svg '));
        });

        it('handles empty string', () => {
            const svg = generateQR('');
            assert.ok(svg.startsWith('<svg '));
        });

        it('handles long strings', () => {
            const longStr = 'a'.repeat(100);
            const svg = generateQR(longStr);
            assert.ok(svg.startsWith('<svg '));
        });
    });
});
