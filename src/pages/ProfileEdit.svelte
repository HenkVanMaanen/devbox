<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';
  import Button from '$components/ui/Button.svelte';
  import ConfigForm from '$components/ConfigForm.svelte';

  interface Props {
    profileId: string;
  }

  let { profileId }: Props = $props();

  let profile = $derived(profilesStore.profiles[profileId]);

  // Load Hetzner options for dropdowns
  $effect(() => {
    if (credentialsStore.hasToken) {
      serversStore.loadOptions(credentialsStore.token);
    }
  });

  // Helper to check if a path is overridden
  function isOverridden(path: string): boolean {
    return profile ? path in profile.overrides : false;
  }

  // Helper to get value (override or global)
  function getValue<T>(path: string): T {
    if (profile && path in profile.overrides) {
      return profile.overrides[path] as T;
    }
    // Get from global config
    const keys = path.split('.');
    let current: unknown = configStore.value;
    for (const key of keys) {
      current = (current as Record<string, unknown>)[key];
    }
    return current as T;
  }

  // Helper to set override value
  function setValue(path: string, value: unknown) {
    if (!profile) return;
    profile.overrides[path] = value;
    profilesStore.save();
  }

  // Toggle override on/off
  function toggleOverride(path: string) {
    if (!profile) return;
    if (path in profile.overrides) {
      delete profile.overrides[path];
    } else {
      // Copy current global value as initial override
      const keys = path.split('.');
      let current: unknown = configStore.value;
      for (const key of keys) {
        current = (current as Record<string, unknown>)[key];
      }
      profile.overrides[path] = clone(current);
    }
    profilesStore.save();
  }

  function goBack() {
    window.location.hash = 'profiles';
  }

  // Toast helper for ConfigForm
  function showToast(message: string, type: 'success' | 'error' | 'info') {
    if (type === 'success') toast.success(message);
    else if (type === 'error') toast.error(message);
    else toast.info(message);
  }
</script>

{#if !profile}
  <div class="text-center py-8">
    <p class="text-muted-foreground mb-4">Profile not found.</p>
    <Button onclick={goBack}>Back to Profiles</Button>
  </div>
{:else}
  <div class="space-y-6 pb-24">
    <div class="flex items-center justify-between">
      <div>
        <Button variant="ghost" size="sm" onclick={goBack}>&larr; Back</Button>
        <h1 class="text-2xl font-bold mt-2">Edit: {profile.name}</h1>
        <p class="text-muted-foreground">Enable overrides to customize settings for this profile.</p>
      </div>
    </div>

    <ConfigForm
      mode="profile"
      {isOverridden}
      {toggleOverride}
      {getValue}
      {setValue}
      {showToast}
      idPrefix="profile-"
    />
  </div>
{/if}
