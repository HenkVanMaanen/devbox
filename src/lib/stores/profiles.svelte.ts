// Profiles store using Svelte 5 runes

import type { Profile, Profiles, GlobalConfig } from '$lib/types';
import { load, save, clone, getNestedValue, uuid } from '$lib/utils/storage';
import { configStore } from './config.svelte';

function createProfilesStore() {
  let profiles = $state<Profiles>(load('profiles') ?? {});
  let defaultProfileId = $state<string | null>(load('defaultProfile'));

  return {
    get profiles() {
      return profiles;
    },
    get defaultProfileId() {
      return defaultProfileId;
    },
    get profileList() {
      return Object.values(profiles);
    },

    // Get a profile by ID
    get(id: string): Profile | undefined {
      return profiles[id];
    },

    // Create a new profile
    create(name: string): string {
      const id = uuid();
      profiles[id] = { id, name, overrides: {} };
      this.save();
      return id;
    },

    // Duplicate a profile
    duplicate(fromId: string, newName: string): string {
      const source = profiles[fromId];
      if (!source) throw new Error(`Profile ${fromId} not found`);

      const id = uuid();
      profiles[id] = {
        id,
        name: newName,
        overrides: clone(source.overrides),
      };
      this.save();
      return id;
    },

    // Update a profile
    update(id: string, updates: Partial<Profile>): void {
      const profile = profiles[id];
      if (!profile) return;

      Object.assign(profile, updates);
      this.save();
    },

    // Delete a profile
    delete(id: string): void {
      delete profiles[id];
      if (defaultProfileId === id) {
        defaultProfileId = null;
        save('defaultProfile', null);
      }
      this.save();
    },

    // Set default profile
    setDefault(id: string | null): void {
      defaultProfileId = id;
      save('defaultProfile', id);
    },

    // Enable an override for a profile
    enableOverride(profileId: string, path: string): void {
      const profile = profiles[profileId];
      if (!profile) return;

      const globalValue = getNestedValue(
        configStore.value as unknown as Record<string, unknown>,
        path
      );
      profile.overrides[path] = clone(globalValue);
      this.save();
    },

    // Disable an override for a profile
    disableOverride(profileId: string, path: string): void {
      const profile = profiles[profileId];
      if (!profile) return;

      delete profile.overrides[path];
      this.save();
    },

    // Get merged config for a profile
    getConfigForProfile(profileId?: string | null): GlobalConfig {
      const baseConfig = clone(configStore.value);
      const id = profileId ?? defaultProfileId;
      if (!id) return baseConfig;

      const profile = profiles[id];
      if (!profile) return baseConfig;

      // Apply overrides
      for (const [path, value] of Object.entries(profile.overrides)) {
        const keys = path.split('.');
        let current: Record<string, unknown> = baseConfig as unknown as Record<string, unknown>;

        for (let i = 0; i < keys.length - 1; i++) {
          const key = keys[i];
          if (key === undefined) continue;
          current = current[key] as Record<string, unknown>;
        }

        const lastKey = keys[keys.length - 1];
        if (lastKey !== undefined) {
          current[lastKey] = clone(value);
        }
      }

      return baseConfig;
    },

    // Save to localStorage
    save(): void {
      save('profiles', profiles);
    },
  };
}

export const profilesStore = createProfilesStore();
