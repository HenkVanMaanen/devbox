<script lang="ts">
  import ConfigForm from '$components/ConfigForm.svelte';
  import Button from '$components/ui/Button.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';

  interface Props {
    profileId: string;
  }

  let { profileId }: Props = $props();

  let profile = $derived(profilesStore.profiles[profileId]);

  // Load Hetzner options for dropdowns
  $effect(() => {
    if (credentialsStore.hasToken) {
      void serversStore.loadOptions(credentialsStore.token);
    }
  });

  // Helper to check if a path is overridden
  function isOverridden(path: string): boolean {
    return profile ? path in profile.overrides : false;
  }

  // Helper to get value (override or global)
  function getValue(path: string): unknown {
    if (profile && path in profile.overrides) {
      return profile.overrides[path];
    }
    // Get from global config
    const keys = path.split('.');
    let current: unknown = configStore.value;
    for (const key of keys) {
      current = (current as Record<string, unknown>)[key];
    }
    return current;
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
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete -- overrides use dynamic paths by design
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
  function showToast(message: string, type: 'error' | 'info' | 'success') {
    if (type === 'success') toast.success(message);
    else if (type === 'error') toast.error(message);
    else toast.info(message);
  }
</script>

{#if !profile}
  <div class="py-8 text-center">
    <p class="text-muted-foreground mb-4">Profile not found.</p>
    <Button onclick={goBack}>Back to Profiles</Button>
  </div>
{:else}
  <div class="space-y-6 pb-24">
    <div class="flex items-center justify-between">
      <div>
        <Button variant="ghost" size="sm" onclick={goBack}>&larr; Back</Button>
        <h1 class="mt-2 text-2xl font-bold">Edit: {profile.name}</h1>
        <p class="text-muted-foreground">Enable overrides to customize settings for this profile.</p>
      </div>
    </div>

    <ConfigForm mode="profile" {isOverridden} {toggleOverride} {getValue} {setValue} {showToast} idPrefix="profile-" />
  </div>
{/if}
