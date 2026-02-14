// Global configuration store using Svelte 5 runes

import type { GlobalConfig } from '$lib/types';

import { clone, deepMerge, getNestedValue, load, save, setNestedValue, uuid } from '$lib/utils/storage';

const DEFAULT_CONFIG: GlobalConfig = {
  autoDelete: {
    enabled: true,
    timeoutMinutes: 90,
    warningMinutes: 5,
  },
  chezmoi: {
    ageKey: '',
    repoUrl: '',
  },
  customCloudInit: {
    mode: 'merge',
    yaml: '',
  },
  git: {
    credential: { host: 'github.com', token: '', username: '' },
  },
  hetzner: {
    baseImage: 'ubuntu-24.04',
    location: 'fsn1',
    serverType: 'cx22',
  },
  services: {
    accessToken: uuid().slice(0, 8),
    acmeEmail: '',
    acmeProvider: 'zerossl',
    actalisEabKey: '',
    actalisEabKeyId: '',
    customAcmeUrl: '',
    customDnsDomain: '',
    customEabKey: '',
    customEabKeyId: '',
    dnsService: 'sslip.io',
    zerosslEabKey: '',
    zerosslEabKeyId: '',
  },
  ssh: {
    keys: [],
  },
};

function createConfigStore() {
  const stored = load<GlobalConfig>('config');
  let config = $state<GlobalConfig>(stored ? deepMerge(DEFAULT_CONFIG, stored) : clone(DEFAULT_CONFIG));

  return {
    // Get a nested value by path
    get(path: string): unknown {
      return getNestedValue(config as unknown as Record<string, unknown>, path);
    },
    // Check if config differs from snapshot
    isDirty(snapshot: GlobalConfig): boolean {
      return JSON.stringify(config) !== JSON.stringify(snapshot);
    },

    // Reset to defaults
    reset(): void {
      config = clone(DEFAULT_CONFIG);
      save('config', config);
    },

    // Restore from snapshot
    restore(snapshot: GlobalConfig): void {
      config = clone(snapshot);
    },

    // Save to localStorage
    save(): void {
      save('config', config);
    },

    // Set a nested value by path
    set(path: string, value: unknown): void {
      setNestedValue(config as unknown as Record<string, unknown>, path, value);
    },

    // Create a snapshot for dirty tracking
    snapshot(): GlobalConfig {
      return clone(config);
    },

    get value() {
      return config;
    },

    set value(newConfig: GlobalConfig) {
      config = newConfig;
    },
  };
}

export const configStore = createConfigStore();
