// Toast notifications store

import type { Toast } from '$lib/types';

import { uuid } from '$lib/utils/storage';

function createToastStore() {
  const toasts = $state<Toast[]>([]);

  function add(message: string, type: Toast['type'], duration = 3000): void {
    const id = uuid();
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
    error(message: string, duration?: number): void {
      add(message, 'error', duration ?? 5000);
    },

    info(message: string, duration?: number): void {
      add(message, 'info', duration);
    },

    remove,

    success(message: string, duration?: number): void {
      add(message, 'success', duration);
    },

    get toasts() {
      return toasts;
    },
  };
}

export const toast = createToastStore();
