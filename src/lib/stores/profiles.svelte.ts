// Profiles store using Svelte 5 runes

import { z } from 'zod';

import type { GlobalConfig, Profile, Profiles } from '$lib/types';

import { profilesSchema } from '$lib/types';
import { clone, getNestedValue, loadValidated, save, uuid } from '$lib/utils/storage';

import { configStore } from './config.svelte';

function createProfilesStore() {
  const profiles = $state<Profiles>(loadValidated('profiles', profilesSchema) ?? {});
  let defaultProfileId = $state<null | string>(loadValidated('defaultProfile', z.string()));

  return {
    // Create a new profile
    create(name: string): string {
      const id = uuid();
      profiles[id] = { id, name, overrides: {} };
      this.save();
      return id;
    },
    get defaultProfileId() {
      return defaultProfileId;
    },
    // Delete a profile
    delete(id: string): void {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete profiles[id];
      if (defaultProfileId === id) {
        defaultProfileId = null;
        save('defaultProfile', null);
      }
      this.save();
    },

    // Disable an override for a profile
    disableOverride(profileId: string, path: string): void {
      const profile = profiles[profileId];
      if (!profile) return;

      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete profile.overrides[path];
      this.save();
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

    // Enable an override for a profile
    enableOverride(profileId: string, path: string): void {
      const profile = profiles[profileId];
      if (!profile) return;

      const globalValue = getNestedValue(configStore.value as unknown as Record<string, unknown>, path);
      profile.overrides[path] = clone(globalValue);
      this.save();
    },

    // Get a profile by ID
    get(id: string): Profile | undefined {
      return profiles[id];
    },

    // Get merged config for a profile
    getConfigForProfile(profileId?: null | string): GlobalConfig {
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

        const lastKey = keys.at(-1);
        if (lastKey !== undefined) {
          current[lastKey] = clone(value);
        }
      }

      return baseConfig;
    },

    get profileList() {
      return Object.values(profiles);
    },

    get profiles() {
      return profiles;
    },

    // Save to localStorage
    save(): void {
      save('profiles', profiles);
    },

    // Set default profile
    setDefault(id: null | string): void {
      defaultProfileId = id;
      save('defaultProfile', id);
    },

    // Update a profile
    update(id: string, updates: Partial<Profile>): void {
      const profile = profiles[id];
      if (!profile) return;

      Object.assign(profile, updates);
      this.save();
    },
  };
}

export const profilesStore = createProfilesStore();
