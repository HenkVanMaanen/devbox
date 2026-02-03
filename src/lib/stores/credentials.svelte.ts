// Credentials store for Hetzner API token

import { load, save, remove } from '$lib/utils/storage';
import * as hetzner from '$lib/api/hetzner';

function createCredentialsStore() {
  let token = $state<string>(load('hetznerToken') ?? '');
  let validating = $state(false);

  return {
    get token() {
      return token;
    },
    set token(value: string) {
      token = value;
    },
    get hasToken() {
      return token.length > 0;
    },
    get validating() {
      return validating;
    },

    // Save token to localStorage
    save(): void {
      save('hetznerToken', token);
    },

    // Clear token
    clear(): void {
      token = '';
      remove('hetznerToken');
    },

    // Validate token with Hetzner API
    async validate(): Promise<boolean> {
      if (!token) return false;

      validating = true;
      try {
        return await hetzner.validateToken(token);
      } finally {
        validating = false;
      }
    },
  };
}

export const credentialsStore = createCredentialsStore();
