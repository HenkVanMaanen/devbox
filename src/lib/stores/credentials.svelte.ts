// Credentials store for Hetzner API token

import * as hetzner from '$lib/api/hetzner';
import { load, remove, save } from '$lib/utils/storage';

function createCredentialsStore() {
  let token = $state<string>(load('hetznerToken') ?? '');
  let validating = $state(false);

  return {
    // Clear token
    clear(): void {
      token = '';
      remove('hetznerToken');
    },
    get hasToken() {
      return token.length > 0;
    },
    // Save token to localStorage
    save(): void {
      save('hetznerToken', token);
    },
    get token() {
      return token;
    },

    set token(value: string) {
      token = value;
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

    get validating() {
      return validating;
    },
  };
}

export const credentialsStore = createCredentialsStore();
