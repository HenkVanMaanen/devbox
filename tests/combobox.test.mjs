import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderSelectCombobox, renderCombobox } from '../web/js/combobox.js';

describe('combobox.js', () => {
    describe('renderSelectCombobox', () => {
        const options = [
            { value: 'a', label: 'Alpha', description: 'First letter' },
            { value: 'b', label: 'Beta', description: 'Second letter' },
            { value: 'c', label: 'Gamma', description: '', disabled: true }
        ];

        it('renders a combobox-single container', () => {
            const html = renderSelectCombobox('test-id', options, 'a', 'Pick one');
            assert.ok(html.includes('combobox-single'));
            assert.ok(html.includes('data-combobox-id="test-id"'));
        });

        it('marks selected option with selected class', () => {
            const html = renderSelectCombobox('test-id', options, 'b', 'Pick one');
            assert.ok(html.includes('data-value="b"'));
            assert.ok(html.includes('\u2713')); // checkmark
        });

        it('uses placeholder when no option selected', () => {
            const html = renderSelectCombobox('test-id', options, 'nonexistent', 'Pick one');
            assert.ok(html.includes('placeholder="Pick one"'));
        });

        it('shows selected label as placeholder when value matches', () => {
            const html = renderSelectCombobox('test-id', options, 'a', 'Pick one');
            assert.ok(html.includes('placeholder="Alpha"'));
        });

        it('marks disabled options', () => {
            const html = renderSelectCombobox('test-id', options, 'a', 'Pick one');
            assert.ok(html.includes('data-disabled'));
        });

        it('sets data-selected attribute on input', () => {
            const html = renderSelectCombobox('test-id', options, 'b', 'Pick one');
            assert.ok(html.includes('data-selected="b"'));
        });

        it('escapes HTML in labels', () => {
            const xssOptions = [{ value: 'x', label: '<script>alert(1)</script>', description: '' }];
            const html = renderSelectCombobox('test-id', xssOptions, '', 'Pick');
            assert.ok(!html.includes('<script>'));
            assert.ok(html.includes('&lt;script&gt;'));
        });

        it('escapes HTML in descriptions used as title', () => {
            const xssOptions = [{ value: 'x', label: 'Test', description: '"onmouseover="alert(1)' }];
            const html = renderSelectCombobox('test-id', xssOptions, '', 'Pick');
            assert.ok(!html.includes('"onmouseover='));
        });

        it('includes search input with autocomplete off', () => {
            const html = renderSelectCombobox('test-id', options, 'a', 'Pick');
            assert.ok(html.includes('autocomplete="off"'));
        });

        it('includes chevron SVG', () => {
            const html = renderSelectCombobox('test-id', options, 'a', 'Pick');
            assert.ok(html.includes('combobox-chevron'));
            assert.ok(html.includes('<svg'));
        });
    });

    describe('renderCombobox (multi-select)', () => {
        const options = [
            { value: 'node@22', label: 'node@22', group: 'Node.js', description: 'Runtime' },
            { value: 'node@20', label: 'node@20', group: 'Node.js', description: 'LTS' },
            { value: 'python@3.12', label: 'python@3.12', group: 'Python', description: 'Latest' }
        ];

        it('renders tags for selected values', () => {
            const html = renderCombobox('pkg', options, ['node@22'], 'Search...', true);
            assert.ok(html.includes('combobox-tag'));
            assert.ok(html.includes('node@22'));
        });

        it('renders remove button on tags', () => {
            const html = renderCombobox('pkg', options, ['node@22'], 'Search...', true);
            assert.ok(html.includes('data-remove="node@22"'));
            assert.ok(html.includes('&times;'));
        });

        it('groups options when grouped=true', () => {
            const html = renderCombobox('pkg', options, [], 'Search...', true);
            assert.ok(html.includes('combobox-group'));
            assert.ok(html.includes('combobox-group-label'));
            assert.ok(html.includes('Node.js'));
            assert.ok(html.includes('Python'));
        });

        it('renders flat list when grouped=false', () => {
            const html = renderCombobox('pkg', options, [], 'Search...', false);
            assert.ok(!html.includes('combobox-group'));
        });

        it('marks selected options in dropdown', () => {
            const html = renderCombobox('pkg', options, ['python@3.12'], 'Search...', true);
            // The selected option should have 'selected' class and checkmark
            const optionMatch = html.match(/data-value="python@3\.12"[^>]*>/);
            assert.ok(optionMatch);
            assert.ok(html.includes('class="combobox-option selected"'));
        });

        it('shows placeholder when nothing selected', () => {
            const html = renderCombobox('pkg', options, [], 'Search...', false);
            assert.ok(html.includes('placeholder="Search..."'));
        });

        it('hides placeholder when items selected', () => {
            const html = renderCombobox('pkg', options, ['node@22'], 'Search...', false);
            assert.ok(html.includes('placeholder=""'));
        });

        it('includes empty state element', () => {
            const html = renderCombobox('pkg', options, [], 'Search...', false);
            assert.ok(html.includes('combobox-empty'));
            assert.ok(html.includes('No results found'));
        });

        it('escapes values in data attributes', () => {
            const xssOptions = [{ value: '"><img src=x>', label: 'XSS', description: '' }];
            const html = renderCombobox('pkg', xssOptions, [], 'Search...', false);
            assert.ok(!html.includes('"><img'));
        });

        it('handles empty options list', () => {
            const html = renderCombobox('pkg', [], [], 'Search...', false);
            assert.ok(html.includes('combobox'));
            assert.ok(html.includes('combobox-empty'));
        });

        it('handles selected values not in options', () => {
            const html = renderCombobox('pkg', options, ['custom@1.0'], 'Search...', false);
            assert.ok(html.includes('combobox-tag'));
            assert.ok(html.includes('custom@1.0'));
        });
    });
});
