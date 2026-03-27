// Setup wizard completion store

import { z } from 'zod';

import { load, loadValidated, save } from '$lib/utils/storage';

function createSetupStore() {
  let completed = $state<boolean>(resolveInitialState());

  return {
    get isComplete() {
      return completed;
    },
    markComplete(): void {
      completed = true;
      save('setupComplete', true);
    },
  };
}

function isExistingUserSetup(): boolean {
  const hasToken = Boolean(loadValidated('hetznerToken', z.string().min(1)));
  const config = load<{ auth?: { users?: unknown[] } }>('config');
  const hasUsers = Array.isArray(config?.auth?.users) && config.auth.users.length > 0;
  return hasToken && hasUsers;
}

function resolveInitialState(): boolean {
  const stored = load<boolean>('setupComplete') ?? false;
  if (stored) return true;

  // Auto-detect existing configured users (upgrade path for existing users)
  if (isExistingUserSetup()) {
    save('setupComplete', true);
    return true;
  }

  return false;
}

export const setupStore = createSetupStore();
