import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock DOM
globalThis.document = {
    querySelectorAll: () => [],
    getElementById: () => null,
    createElement: () => ({ className: '', textContent: '', style: {}, remove: () => {} }),
    addEventListener: () => {},
    documentElement: { style: { setProperty: () => {} }, classList: { add: () => {}, remove: () => {} } },
    querySelector: () => null,
    head: { appendChild: () => {} },
    body: { contains: () => true }
};
globalThis.window = {
    location: { hash: '' },
    matchMedia: () => ({ matches: true, addEventListener: () => {} }),
    addEventListener: () => {}
};

const { state, setState, setRenderCallback, router } = await import('../web/js/state.js');

describe('state.js', () => {
    let renderCalled;

    beforeEach(() => {
        renderCalled = false;
        setRenderCallback(() => { renderCalled = true; });
        // Reset state
        Object.assign(state, {
            page: 'dashboard',
            servers: [],
            loading: false,
            error: null,
            creating: false,
            createProgress: '',
            serverTypes: [],
            locations: [],
            images: [],
            loadingHetznerOptions: false,
            selectedProfileId: null,
            editingProfileId: null
        });
    });

    describe('setState', () => {
        it('updates state properties', () => {
            setState({ loading: true });
            assert.equal(state.loading, true);
        });

        it('triggers render callback', () => {
            setState({ loading: true });
            assert.equal(renderCalled, true);
        });

        it('merges multiple properties', () => {
            setState({ loading: true, error: 'test error' });
            assert.equal(state.loading, true);
            assert.equal(state.error, 'test error');
        });

        it('does not remove existing properties', () => {
            setState({ loading: true });
            setState({ error: 'err' });
            assert.equal(state.loading, true);
            assert.equal(state.error, 'err');
        });

        it('can set arrays', () => {
            setState({ servers: [{ id: 1 }] });
            assert.equal(state.servers.length, 1);
            assert.equal(state.servers[0].id, 1);
        });

        it('does not call render if no callback set', () => {
            setRenderCallback(null);
            // Should not throw
            setState({ loading: true });
            assert.equal(state.loading, true);
        });
    });

    describe('router', () => {
        it('sets page from hash', () => {
            window.location.hash = '#config';
            router();
            assert.equal(state.page, 'config');
        });

        it('defaults to dashboard when no hash', () => {
            window.location.hash = '';
            router();
            assert.equal(state.page, 'dashboard');
        });

        it('handles hash with sub-path', () => {
            window.location.hash = '#profiles/edit';
            router();
            assert.equal(state.page, 'profiles');
        });

        it('clears error on navigation', () => {
            setState({ error: 'some error' });
            window.location.hash = '#credentials';
            router();
            assert.equal(state.error, null);
        });
    });

    describe('state initial values', () => {
        it('has correct default page', () => {
            assert.equal(state.page, 'dashboard');
        });

        it('starts with empty servers', () => {
            assert.deepEqual(state.servers, []);
        });

        it('starts not loading', () => {
            assert.equal(state.loading, false);
        });

        it('starts not creating', () => {
            assert.equal(state.creating, false);
        });

        it('has no selected profile', () => {
            assert.equal(state.selectedProfileId, null);
        });
    });
});
