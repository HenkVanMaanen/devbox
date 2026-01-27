import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { UI, cn, escapeHtml, escapeAttr } from '../web/js/ui.js';

describe('ui.js', () => {
    describe('escapeHtml', () => {
        it('escapes ampersands', () => {
            assert.equal(escapeHtml('a & b'), 'a &amp; b');
        });

        it('escapes less-than', () => {
            assert.equal(escapeHtml('<script>'), '&lt;script&gt;');
        });

        it('escapes greater-than', () => {
            assert.equal(escapeHtml('a > b'), 'a &gt; b');
        });

        it('escapes double quotes', () => {
            assert.equal(escapeHtml('"hello"'), '&quot;hello&quot;');
        });

        it('escapes single quotes', () => {
            assert.equal(escapeHtml("it's"), "it&#39;s");
        });

        it('handles null', () => {
            assert.equal(escapeHtml(null), '');
        });

        it('handles undefined', () => {
            assert.equal(escapeHtml(undefined), '');
        });

        it('converts numbers to strings', () => {
            assert.equal(escapeHtml(42), '42');
        });

        it('handles empty string', () => {
            assert.equal(escapeHtml(''), '');
        });

        it('escapes multiple special chars', () => {
            assert.equal(escapeHtml('<a href="x&y">'), '&lt;a href=&quot;x&amp;y&quot;&gt;');
        });
    });

    describe('escapeAttr', () => {
        it('escapes ampersands', () => {
            assert.equal(escapeAttr('a & b'), 'a &amp; b');
        });

        it('escapes double quotes', () => {
            assert.equal(escapeAttr('"value"'), '&quot;value&quot;');
        });

        it('escapes single quotes', () => {
            assert.equal(escapeAttr("it's"), "it&#39;s");
        });

        it('escapes angle brackets', () => {
            assert.equal(escapeAttr('<>'), '&lt;&gt;');
        });

        it('handles null', () => {
            assert.equal(escapeAttr(null), '');
        });

        it('handles undefined', () => {
            assert.equal(escapeAttr(undefined), '');
        });

        it('converts non-strings', () => {
            assert.equal(escapeAttr(123), '123');
        });
    });

    describe('cn', () => {
        it('joins classes with space', () => {
            assert.equal(cn('a', 'b', 'c'), 'a b c');
        });

        it('filters out falsy values', () => {
            assert.equal(cn('a', null, 'b', undefined, 'c', '', false, 0), 'a b c');
        });

        it('handles single class', () => {
            assert.equal(cn('only'), 'only');
        });

        it('returns empty string for all falsy', () => {
            assert.equal(cn(null, undefined, false), '');
        });
    });

    describe('UI constants', () => {
        it('has card classes defined', () => {
            assert.ok(UI.card);
            assert.ok(UI.cardHeader);
            assert.ok(UI.cardBody);
        });

        it('has button classes defined', () => {
            assert.ok(UI.btn);
            assert.ok(UI.btnPrimary);
            assert.ok(UI.btnSecondary);
            assert.ok(UI.btnDestructive);
        });

        it('has form element classes defined', () => {
            assert.ok(UI.input);
            assert.ok(UI.textarea);
            assert.ok(UI.checkbox);
        });

        it('has layout classes defined', () => {
            assert.ok(UI.stack);
            assert.ok(UI.row);
            assert.ok(UI.grid2);
        });

        it('button includes min-h for touch targets', () => {
            assert.ok(UI.btn.includes('min-h-'));
        });

        it('input includes focus ring classes', () => {
            assert.ok(UI.input.includes('focus:ring'));
        });
    });
});
