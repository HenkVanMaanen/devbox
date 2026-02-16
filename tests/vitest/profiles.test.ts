import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('profiles store', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
  });

  async function getStores() {
    const { configStore } = await import('$lib/stores/config.svelte');
    const { profilesStore } = await import('$lib/stores/profiles.svelte');
    return { configStore, profilesStore };
  }

  it('is initially empty when no localStorage', async () => {
    const { profilesStore } = await getStores();
    expect(profilesStore.profileList).toHaveLength(0);
    expect(profilesStore.profiles).toEqual({});
    expect(profilesStore.defaultProfileId).toBeNull();
  });

  it('create() adds profile and returns id', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Test Profile');
    expect(id).toBeTruthy();
    expect(typeof id).toBe('string');
    expect(profilesStore.profileList).toHaveLength(1);
    const profile = profilesStore.get(id);
    expect(profile).toBeDefined();
    expect(profile?.name).toBe('Test Profile');
    expect(profile?.overrides).toEqual({});
  });

  it('create() saves to localStorage', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Saved Profile');
    const stored = JSON.parse(localStorage.getItem('devbox_profiles') ?? '{}');
    expect(stored[id]).toBeDefined();
    expect(stored[id].name).toBe('Saved Profile');
  });

  it('delete() removes profile', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('To Delete');
    expect(profilesStore.profileList).toHaveLength(1);

    profilesStore.delete(id);
    expect(profilesStore.profileList).toHaveLength(0);
    expect(profilesStore.get(id)).toBeUndefined();
  });

  it('delete() clears defaultProfileId if matching', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Default');
    profilesStore.setDefault(id);
    expect(profilesStore.defaultProfileId).toBe(id);

    profilesStore.delete(id);
    expect(profilesStore.defaultProfileId).toBeNull();
  });

  it('delete() does not clear defaultProfileId if not matching', async () => {
    const { profilesStore } = await getStores();
    const id1 = profilesStore.create('Profile 1');
    const id2 = profilesStore.create('Profile 2');
    profilesStore.setDefault(id1);

    profilesStore.delete(id2);
    expect(profilesStore.defaultProfileId).toBe(id1);
  });

  it('duplicate() clones profile with overrides', async () => {
    const { profilesStore } = await getStores();
    const originalId = profilesStore.create('Original');
    profilesStore.update(originalId, { overrides: { 'hetzner.location': 'nbg1' } });

    const cloneId = profilesStore.duplicate(originalId, 'Cloned');
    const cloned = profilesStore.get(cloneId);
    expect(cloned).toBeDefined();
    expect(cloned?.name).toBe('Cloned');
    expect(cloned?.overrides).toEqual({ 'hetzner.location': 'nbg1' });
    expect(cloned?.id).toBe(cloneId);
    expect(cloned?.id).not.toBe(originalId);
  });

  it('duplicate() throws for non-existent source', async () => {
    const { profilesStore } = await getStores();
    expect(() => profilesStore.duplicate('non-existent', 'Clone')).toThrow('Profile non-existent not found');
  });

  it('get() returns profile by id', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Lookup');
    const profile = profilesStore.get(id);
    expect(profile).toBeDefined();
    expect(profile?.id).toBe(id);
    expect(profile?.name).toBe('Lookup');
  });

  it('get() returns undefined for non-existent id', async () => {
    const { profilesStore } = await getStores();
    expect(profilesStore.get('does-not-exist')).toBeUndefined();
  });

  it('enableOverride() copies value from configStore', async () => {
    const { configStore, profilesStore } = await getStores();
    const id = profilesStore.create('Override Test');

    // The configStore should have default hetzner.location = 'fsn1'
    expect(configStore.get('hetzner.location')).toBe('fsn1');

    profilesStore.enableOverride(id, 'hetzner.location');
    const profile = profilesStore.get(id);
    expect(profile?.overrides['hetzner.location']).toBe('fsn1');
  });

  it('disableOverride() removes override', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Disable Test');

    profilesStore.enableOverride(id, 'hetzner.location');
    expect(profilesStore.get(id)?.overrides['hetzner.location']).toBeDefined();

    profilesStore.disableOverride(id, 'hetzner.location');
    expect(profilesStore.get(id)?.overrides['hetzner.location']).toBeUndefined();
  });

  it('getConfigForProfile() returns base config when no profile', async () => {
    const { configStore, profilesStore } = await getStores();
    const config = profilesStore.getConfigForProfile(null);
    expect(config.hetzner.location).toBe(configStore.value.hetzner.location);
    expect(config.hetzner.serverType).toBe(configStore.value.hetzner.serverType);
  });

  it('getConfigForProfile() applies overrides to config', async () => {
    const { configStore, profilesStore } = await getStores();
    const id = profilesStore.create('Merge Test');

    // Enable and then modify an override
    profilesStore.enableOverride(id, 'hetzner.location');
    const profile = profilesStore.get(id);
    expect(profile).toBeDefined();
    profile!.overrides['hetzner.location'] = 'nbg1';
    profilesStore.save();

    const config = profilesStore.getConfigForProfile(id);
    expect(config.hetzner.location).toBe('nbg1');
    // Other values should remain from global config
    expect(config.hetzner.serverType).toBe(configStore.value.hetzner.serverType);
  });

  it('getConfigForProfile() uses defaultProfileId when no id passed', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Default Profile');
    profilesStore.enableOverride(id, 'hetzner.location');
    const profile = profilesStore.get(id);
    profile!.overrides['hetzner.location'] = 'hel1';
    profilesStore.save();
    profilesStore.setDefault(id);

    const config = profilesStore.getConfigForProfile();
    expect(config.hetzner.location).toBe('hel1');
  });

  it('setDefault() sets and saves default profile id', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('My Default');
    profilesStore.setDefault(id);
    expect(profilesStore.defaultProfileId).toBe(id);

    const stored = JSON.parse(localStorage.getItem('devbox_default_profile') ?? 'null');
    expect(stored).toBe(id);
  });

  it('update() merges updates into profile', async () => {
    const { profilesStore } = await getStores();
    const id = profilesStore.create('Before Update');
    profilesStore.update(id, { name: 'After Update' });
    expect(profilesStore.get(id)?.name).toBe('After Update');
  });

  it('profileList returns array of profiles', async () => {
    const { profilesStore } = await getStores();
    profilesStore.create('Alpha');
    profilesStore.create('Beta');
    profilesStore.create('Gamma');
    const list = profilesStore.profileList;
    expect(list).toHaveLength(3);
    const names = list.map((p) => p.name);
    expect(names).toContain('Alpha');
    expect(names).toContain('Beta');
    expect(names).toContain('Gamma');
  });
});
