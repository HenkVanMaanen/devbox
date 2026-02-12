<script lang="ts">
  import { configStore } from '$lib/stores/config.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';
  import type { GlobalConfig, Profiles } from '$lib/types';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import FloatingActions from '$components/FloatingActions.svelte';
  import ConfigForm from '$components/ConfigForm.svelte';

  // Snapshot for dirty tracking
  let snapshot = $state<GlobalConfig>(clone(configStore.value));
  let dirty = $derived(JSON.stringify(configStore.value) !== JSON.stringify(snapshot));

  // Load Hetzner options for dropdowns
  $effect(() => {
    if (credentialsStore.hasToken) {
      serversStore.loadOptions(credentialsStore.token);
    }
  });

  function save() {
    configStore.save();
    snapshot = clone(configStore.value);
    toast.success('Configuration saved');
  }

  function discard() {
    configStore.value = clone(snapshot);
    toast.info('Changes discarded');
  }

  // getValue/setValue for ConfigForm in global mode
  function getValue<T>(path: string): T {
    const keys = path.split('.');
    let current: unknown = configStore.value;
    for (const key of keys) {
      current = (current as Record<string, unknown>)[key];
    }
    return current as T;
  }

  function setValue(path: string, value: unknown) {
    const keys = path.split('.');
    let current: Record<string, unknown> = configStore.value as unknown as Record<string, unknown>;
    for (let i = 0; i < keys.length - 1; i++) {
      current = current[keys[i]!] as Record<string, unknown>;
    }
    current[keys[keys.length - 1]!] = value;
  }

  // Toast helper for ConfigForm
  function showToast(message: string, type: 'success' | 'error' | 'info') {
    if (type === 'success') toast.success(message);
    else if (type === 'error') toast.error(message);
    else toast.info(message);
  }

  // Export configuration
  let fileInputRef: HTMLInputElement | undefined = $state();

  function exportConfig() {
    const exportData = {
      version: 1,
      exportedAt: new Date().toISOString(),
      // New format
      config: configStore.value,
      profiles: profilesStore.profiles,
      defaultProfileId: profilesStore.defaultProfileId,
      hetznerToken: credentialsStore.token,
      theme: themeStore.themeId,
      serverTokens: serversStore.serverTokens,
      // Old format (for backwards compatibility)
      globalConfig: configStore.value,
      defaultProfile: profilesStore.defaultProfileId,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `devbox-config-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Configuration exported');
  }

  function triggerImport() {
    fileInputRef?.click();
  }

  function handleImport(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string);

        // Support both new format (config) and old format (globalConfig)
        const rawConfig = data.config || data.globalConfig;
        if (!rawConfig) {
          toast.error('Invalid config file: missing config or globalConfig');
          return;
        }

        // Import config (merge with defaults to handle missing fields)
        configStore.value = { ...configStore.value, ...rawConfig } as GlobalConfig;
        configStore.save();
        snapshot = clone(configStore.value);

        // Import profiles if present
        if (data.profiles) {
          const profiles = data.profiles as Profiles;
          for (const [id, profile] of Object.entries(profiles)) {
            if (!profilesStore.get(id)) {
              profilesStore.profiles[id] = profile;
            }
          }
          profilesStore.save();
        }

        // Set default profile if present (support both formats)
        const defaultProfileId = data.defaultProfileId || data.defaultProfile;
        if (defaultProfileId) {
          profilesStore.setDefault(defaultProfileId);
        }

        // Import Hetzner token if present
        if (data.hetznerToken) {
          credentialsStore.token = data.hetznerToken;
          credentialsStore.save();
        }

        // Import theme if present
        if (data.theme) {
          themeStore.setTheme(data.theme);
        }

        // Import server tokens if present
        if (data.serverTokens) {
          for (const [name, token] of Object.entries(data.serverTokens)) {
            serversStore.saveServerToken(name, token as string);
          }
        }

        toast.success('Configuration imported successfully');
      } catch (err) {
        toast.error('Failed to parse config file');
        console.error('Import error:', err);
      }
    };
    reader.readAsText(file);

    // Reset input so the same file can be imported again
    input.value = '';
  }
</script>

<div class="space-y-6 pb-24">
  <h1 class="text-2xl font-bold">Global Configuration</h1>

  <!-- All form fields via ConfigForm -->
  <ConfigForm mode="global" {getValue} {setValue} {showToast} idPrefix="global-" />

  <Card title="Backup & Restore">
    <p class="text-sm text-muted-foreground mb-4">
      Export your configuration and profiles to a JSON file, or import a previously exported configuration.
    </p>
    <div class="flex gap-3">
      <Button variant="secondary" onclick={exportConfig}>Export Configuration</Button>
      <Button variant="secondary" onclick={triggerImport}>Import Configuration</Button>
      <input
        bind:this={fileInputRef}
        type="file"
        accept=".json"
        class="hidden"
        onchange={handleImport}
      />
    </div>
  </Card>
</div>

{#if dirty}
  <FloatingActions onSave={save} onDiscard={discard} />
{/if}
