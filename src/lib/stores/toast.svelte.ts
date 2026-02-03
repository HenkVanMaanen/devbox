// Toast notifications store

import type { Toast } from '$lib/types';

function createToastStore() {
  let toasts = $state<Toast[]>([]);

  function add(message: string, type: Toast['type'], duration = 3000): void {
    const id = crypto.randomUUID();
    toasts.push({ id, message, type });

    setTimeout(() => {
      remove(id);
    }, duration);
  }

  function remove(id: string): void {
    const index = toasts.findIndex((t) => t.id === id);
    if (index !== -1) {
      toasts.splice(index, 1);
    }
  }

  return {
    get toasts() {
      return toasts;
    },

    success(message: string, duration?: number): void {
      add(message, 'success', duration);
    },

    error(message: string, duration?: number): void {
      add(message, 'error', duration ?? 5000);
    },

    info(message: string, duration?: number): void {
      add(message, 'info', duration);
    },

    remove,
  };
}

export const toast = createToastStore();
