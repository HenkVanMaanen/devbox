import { mount, unmount } from 'svelte';
import { describe, expect, it, afterEach } from 'vitest';

import Input from '$components/ui/Input.svelte';

describe('Input component', () => {
  let cleanup: (() => void) | undefined;

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
    document.body.innerHTML = '';
  });

  function mountInput(props: Record<string, unknown> = {}) {
    const target = document.createElement('div');
    document.body.appendChild(target);
    const instance = mount(Input, { target, props });
    cleanup = () => unmount(instance);
    return target;
  }

  it('renders a label when label prop is provided', () => {
    const target = mountInput({ label: 'Email' });
    const label = target.querySelector('label');
    expect(label).not.toBeNull();
    expect(label?.textContent).toBe('Email');
  });

  it('does not render label when label prop is omitted', () => {
    const target = mountInput({});
    const label = target.querySelector('label');
    expect(label).toBeNull();
  });

  it('sets aria-invalid when error is provided', () => {
    const target = mountInput({ error: 'Required field' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-invalid')).toBe('true');
  });

  it('does not set aria-invalid when no error', () => {
    const target = mountInput({});
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-invalid')).toBeNull();
  });

  it('sets aria-describedby when help is provided', () => {
    const target = mountInput({ help: 'Enter your email' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-describedby')).toBeTruthy();
    const descId = input?.getAttribute('aria-describedby') ?? '';
    const desc = document.getElementById(descId);
    expect(desc?.textContent).toBe('Enter your email');
  });

  it('sets aria-describedby when error is provided', () => {
    const target = mountInput({ error: 'Invalid email' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-describedby')).toBeTruthy();
    const descId = input?.getAttribute('aria-describedby') ?? '';
    const desc = document.getElementById(descId);
    expect(desc?.textContent).toBe('Invalid email');
  });

  it('shows error text instead of help text when both provided', () => {
    const target = mountInput({ help: 'Help text', error: 'Error text' });
    expect(target.textContent).toContain('Error text');
    expect(target.textContent).not.toContain('Help text');
  });

  it('passes through HTML input attributes', () => {
    const target = mountInput({ type: 'password', placeholder: 'Enter password' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('type')).toBe('password');
    expect(input?.getAttribute('placeholder')).toBe('Enter password');
  });
});
