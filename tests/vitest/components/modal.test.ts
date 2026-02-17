import { mount, unmount } from 'svelte';
import { createRawSnippet } from 'svelte';
import { describe, expect, it, vi, afterEach } from 'vitest';

import Modal from '$components/ui/Modal.svelte';

describe('Modal component', () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
    document.body.innerHTML = '';
  });

  const childSnippet = createRawSnippet(() => ({
    render: () => '<p>Modal content</p>',
  }));

  const actionsSnippet = createRawSnippet(() => ({
    render: () => '<button type="button">OK</button>',
  }));

  function mountModal(props: Record<string, unknown> = {}) {
    const target = document.createElement('div');
    document.body.appendChild(target);
    const defaultProps = {
      children: childSnippet,
      onClose: vi.fn(),
      open: true,
      title: 'Test Modal',
    };
    const instance = mount(Modal, { target, props: { ...defaultProps, ...props } });
    cleanup = () => unmount(instance);
    return { target, onClose: (props.onClose ?? defaultProps.onClose) as ReturnType<typeof vi.fn> };
  }

  it('renders when open is true', () => {
    mountModal({ open: true });
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
  });

  it('does not render when open is false', () => {
    mountModal({ open: false });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it('displays the title', () => {
    mountModal({ title: 'My Title' });
    const title = document.querySelector('#modal-title');
    expect(title?.textContent).toBe('My Title');
  });

  it('has correct ARIA attributes', () => {
    mountModal();
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute('aria-modal')).toBe('true');
    expect(dialog?.getAttribute('aria-labelledby')).toBe('modal-title');
  });

  it('renders children content', () => {
    mountModal();
    expect(document.body.textContent).toContain('Modal content');
  });

  it('renders actions when provided', () => {
    mountModal({ actions: actionsSnippet });
    const okButton = document.querySelector('[role="dialog"] button');
    expect(okButton?.textContent).toBe('OK');
  });

  it('calls onClose when Escape is pressed', () => {
    const { onClose } = mountModal();
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose when backdrop is clicked', () => {
    const { onClose } = mountModal();
    const backdrop = document.querySelector('[role="dialog"]') as HTMLElement;
    backdrop?.click();
    expect(onClose).toHaveBeenCalled();
  });
});
