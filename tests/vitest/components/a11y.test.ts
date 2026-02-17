import { mount, unmount } from 'svelte';
import { afterEach, describe, expect, it } from 'vitest';
import { axe } from 'vitest-axe';

import Input from '$components/ui/Input.svelte';

describe('Input accessibility', () => {
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

  it('input with label has no a11y violations', async () => {
    // Pass explicit id so label for= matches input id (Input.svelte uses {id} on <input>)
    const target = mountInput({ id: 'username-input', label: 'Username' });
    const results = await axe(target);
    expect(results.violations).toEqual([]);
  });

  it('input with error has correct aria attributes', () => {
    const target = mountInput({ id: 'email-input', label: 'Email', error: 'Invalid email' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-invalid')).toBe('true');
    expect(input?.getAttribute('aria-describedby')).toBeTruthy();

    // Verify the described-by element exists and contains the error
    const descId = input?.getAttribute('aria-describedby') ?? '';
    const desc = document.getElementById(descId);
    expect(desc).not.toBeNull();
    expect(desc?.textContent).toBe('Invalid email');
  });

  it('input with help text has correct aria-describedby', () => {
    const target = mountInput({ id: 'password-input', label: 'Password', help: 'Must be 8+ characters' });
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-describedby')).toBeTruthy();

    const descId = input?.getAttribute('aria-describedby') ?? '';
    const desc = document.getElementById(descId);
    expect(desc).not.toBeNull();
    expect(desc?.textContent).toBe('Must be 8+ characters');
  });

  it('input without label or help has no aria-describedby', () => {
    const target = mountInput({});
    const input = target.querySelector('input');
    expect(input?.getAttribute('aria-describedby')).toBeNull();
  });

  it('label for attribute matches input id', () => {
    const target = mountInput({ id: 'name-input', label: 'Name' });
    const label = target.querySelector('label');
    const input = target.querySelector('input');
    expect(label?.getAttribute('for')).toBeTruthy();
    expect(label?.getAttribute('for')).toBe(input?.getAttribute('id'));
  });
});
