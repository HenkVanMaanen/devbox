import { mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import Toast from '$components/ui/Toast.svelte';
import { toast } from '$lib/stores/toast.svelte';

// Polyfill Element.animate for happy-dom (used by Svelte fly transition)
if (typeof Element.prototype.animate !== 'function') {
  Element.prototype.animate = function () {
    return {
      cancel: () => {},
      finish: () => {},
      finished: Promise.resolve(),
      onfinish: null,
    } as unknown as Animation;
  };
}

describe('Toast component', () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    // Clear all toasts
    for (const t of [...toast.toasts]) {
      toast.remove(t.id);
    }
    cleanup?.();
    cleanup = undefined;
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  function mountToast() {
    const target = document.createElement('div');
    document.body.appendChild(target);
    const instance = mount(Toast, { target });
    cleanup = () => unmount(instance);
    return target;
  }

  it('renders toast container with status role', () => {
    const target = mountToast();
    const container = target.querySelector('[role="status"]');
    expect(container).not.toBeNull();
  });

  it('renders dismiss button for toast messages', async () => {
    mountToast();
    toast.success('Test message');
    await vi.advanceTimersByTimeAsync(0);
    const dismissBtn = document.querySelector('[aria-label="Dismiss"]');
    expect(dismissBtn).not.toBeNull();
  });

  it('displays toast message text', async () => {
    mountToast();
    toast.info('Hello World');
    await vi.advanceTimersByTimeAsync(0);
    expect(document.body.textContent).toContain('Hello World');
  });
});
