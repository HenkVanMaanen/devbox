// Global configuration store using Svelte 5 runes

import type { GlobalConfig } from '$lib/types';
import { load, save, clone, deepMerge, getNestedValue, setNestedValue, uuid } from '$lib/utils/storage';

const DEFAULT_CONFIG: GlobalConfig = {
  ssh: {
    keys: [],
  },
  git: {
    userName: '',
    userEmail: '',
    credentials: [],
  },
  shell: {
    default: 'fish',
    starship: true,
  },
  services: {
    codeServer: true,
    claudeTerminal: true,
    shellTerminal: true,
    accessToken: uuid().slice(0, 8),
    dnsService: 'sslip.io',
    acmeProvider: 'zerossl',
    acmeEmail: '',
    zerosslEabKeyId: '',
    zerosslEabKey: '',
    actalisEabKeyId: '',
    actalisEabKey: '',
    customAcmeUrl: '',
    customEabKeyId: '',
    customEabKey: '',
  },
  hetzner: {
    serverType: 'cx22',
    location: 'fsn1',
    baseImage: 'ubuntu-24.04',
  },
  autoDelete: {
    enabled: true,
    timeoutMinutes: 90,
    warningMinutes: 5,
  },
  claude: {
    apiKey: '',
    settings: '',
    credentialsJson: null,
    theme: '',
    skipPermissions: false,
  },
  packages: {
    mise: [],
    apt: [],
  },
  repos: [],
  envVars: [],
};

function createConfigStore() {
  const stored = load<GlobalConfig>('config');
  let config = $state<GlobalConfig>(stored ? deepMerge(DEFAULT_CONFIG, stored) : clone(DEFAULT_CONFIG));

  return {
    get value() {
      return config;
    },
    set value(newConfig: GlobalConfig) {
      config = newConfig;
    },

    // Get a nested value by path
    get<T>(path: string): T | undefined {
      return getNestedValue<T>(config as unknown as Record<string, unknown>, path);
    },

    // Set a nested value by path
    set(path: string, value: unknown): void {
      setNestedValue(config as unknown as Record<string, unknown>, path, value);
    },

    // Save to localStorage
    save(): void {
      save('config', config);
    },

    // Reset to defaults
    reset(): void {
      config = clone(DEFAULT_CONFIG);
      save('config', config);
    },

    // Create a snapshot for dirty tracking
    snapshot(): GlobalConfig {
      return clone(config);
    },

    // Check if config differs from snapshot
    isDirty(snapshot: GlobalConfig): boolean {
      return JSON.stringify(config) !== JSON.stringify(snapshot);
    },

    // Restore from snapshot
    restore(snapshot: GlobalConfig): void {
      config = clone(snapshot);
    },
  };
}

export const configStore = createConfigStore();
