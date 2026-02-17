import { mount, unmount } from 'svelte';
import { createRawSnippet } from 'svelte';
import { describe, expect, it, afterEach } from 'vitest';

import Button from '$components/ui/Button.svelte';

describe('Button component', () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
    document.body.innerHTML = '';
  });

  const childSnippet = createRawSnippet(() => ({
    render: () => '<span>Click me</span>',
  }));

  function mountButton(props: Record<string, unknown> = {}) {
    const target = document.createElement('div');
    document.body.appendChild(target);
    const instance = mount(Button, {
      target,
      props: { children: childSnippet, ...props },
    });
    cleanup = () => unmount(instance);
    return target;
  }

  it('renders children content', () => {
    const target = mountButton();
    expect(target.textContent).toContain('Click me');
  });

  it('applies primary variant classes by default', () => {
    const target = mountButton();
    const button = target.querySelector('button');
    expect(button?.className).toContain('bg-primary');
  });

  it('applies destructive variant classes', () => {
    const target = mountButton({ variant: 'destructive' });
    const button = target.querySelector('button');
    expect(button?.className).toContain('bg-destructive');
  });

  it('applies secondary variant classes', () => {
    const target = mountButton({ variant: 'secondary' });
    const button = target.querySelector('button');
    expect(button?.className).toContain('bg-muted');
  });

  it('applies ghost variant classes', () => {
    const target = mountButton({ variant: 'ghost' });
    const button = target.querySelector('button');
    expect(button?.className).toContain('hover:bg-muted');
  });

  it('is disabled when disabled prop is true', () => {
    const target = mountButton({ disabled: true });
    const button = target.querySelector('button');
    expect(button?.disabled).toBe(true);
  });

  it('is disabled when loading is true', () => {
    const target = mountButton({ loading: true });
    const button = target.querySelector('button');
    expect(button?.disabled).toBe(true);
  });

  it('shows spinner when loading', () => {
    const target = mountButton({ loading: true });
    const spinner = target.querySelector('.animate-spin');
    expect(spinner).not.toBeNull();
  });

  it('does not show spinner when not loading', () => {
    const target = mountButton({ loading: false });
    const spinner = target.querySelector('.animate-spin');
    expect(spinner).toBeNull();
  });
});
