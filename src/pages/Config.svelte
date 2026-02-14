<script lang="ts">
  import type { GlobalConfig, Profiles } from '$lib/types';

  import ConfigForm from '$components/ConfigForm.svelte';
  import FloatingActions from '$components/FloatingActions.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';

  // Snapshot for dirty tracking
  let snapshot = $state<GlobalConfig>(clone(configStore.value));
  let dirty = $derived(JSON.stringify(configStore.value) !== JSON.stringify(snapshot));

  // Load Hetzner options for dropdowns
  $effect(() => {
    if (credentialsStore.hasToken) {
      void serversStore.loadOptions(credentialsStore.token);
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
  function getValue(path: string): unknown {
    const keys = path.split('.');
    let current: unknown = configStore.value;
    for (const key of keys) {
      current = (current as Record<string, unknown>)[key];
    }
    return current;
  }

  function setValue(path: string, value: unknown) {
    const keys = path.split('.');
    let current: Record<string, unknown> = configStore.value as unknown as Record<string, unknown>;
    for (let i = 0; i < keys.length - 1; i++) {
      const k = keys[i];
      if (k === undefined) {
        continue;
      }
      current = current[k] as Record<string, unknown>;
    }
    const lastKey = keys.at(-1);
    if (lastKey !== undefined) {
      current[lastKey] = value;
    }
  }

  // Toast helper for ConfigForm
  function showToast(message: string, type: 'error' | 'info' | 'success') {
    if (type === 'success') toast.success(message);
    else if (type === 'error') toast.error(message);
    else toast.info(message);
  }

  // Export configuration
  let fileInputRef: HTMLInputElement | undefined = $state();

  function exportConfig() {
    const exportData = {
      // New format
      config: configStore.value,
      defaultProfile: profilesStore.defaultProfileId,
      defaultProfileId: profilesStore.defaultProfileId,
      exportedAt: new Date().toISOString(),
      // Old format (for backwards compatibility)
      globalConfig: configStore.value,
      hetznerToken: credentialsStore.token,
      profiles: profilesStore.profiles,
      serverTokens: serversStore.serverTokens,
      theme: themeStore.themeId,
      version: 1,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `devbox-config-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(a);
    a.click();
    a.remove();
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

    void file.text().then((text) => {
      try {
        const data = JSON.parse(text) as Record<string, unknown>;

        // Support both new format (config) and old format (globalConfig)
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- intentional: falsy check
        const rawConfig = data['config'] || data['globalConfig'];
        if (!rawConfig) {
          toast.error('Invalid config file: missing config or globalConfig');
          return;
        }

        // Import config (merge with defaults to handle missing fields)
        configStore.value = { ...configStore.value, ...(rawConfig as Partial<GlobalConfig>) } as GlobalConfig;
        configStore.save();
        snapshot = clone(configStore.value);

        // Import profiles if present
        if (data['profiles']) {
          const profiles = data['profiles'] as Profiles;
          for (const [id, profile] of Object.entries(profiles)) {
            if (!profilesStore.get(id)) {
              profilesStore.profiles[id] = profile;
            }
          }
          profilesStore.save();
        }

        // Set default profile if present (support both formats)
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- intentional: falsy check
        const defaultProfileId = (data['defaultProfileId'] || data['defaultProfile']) as string | undefined;
        if (defaultProfileId) {
          profilesStore.setDefault(defaultProfileId);
        }

        // Import Hetzner token if present
        if (data['hetznerToken']) {
          credentialsStore.token = data['hetznerToken'] as string;
          credentialsStore.save();
        }

        // Import theme if present
        if (data['theme']) {
          themeStore.setTheme(data['theme'] as string);
        }

        // Import server tokens if present
        if (data['serverTokens']) {
          for (const [name, token] of Object.entries(data['serverTokens'] as Record<string, string>)) {
            serversStore.saveServerToken(name, token);
          }
        }

        toast.success('Configuration imported successfully');
      } catch (error) {
        toast.error('Failed to parse config file');
        console.error('Import error:', error);
      }
    });

    // Reset input so the same file can be imported again
    input.value = '';
  }
</script>

<div class="space-y-6 pb-24">
  <h1 class="text-2xl font-bold">Global Configuration</h1>

  <!-- All form fields via ConfigForm -->
  <ConfigForm mode="global" {getValue} {setValue} {showToast} idPrefix="global-" />

  <Card title="Backup & Restore">
    <p class="text-muted-foreground mb-4 text-sm">
      Export your configuration and profiles to a JSON file, or import a previously exported configuration.
    </p>
    <div class="flex gap-3">
      <Button variant="secondary" onclick={exportConfig}>Export Configuration</Button>
      <Button variant="secondary" onclick={triggerImport}>Import Configuration</Button>
      <input bind:this={fileInputRef} type="file" accept=".json" class="hidden" onchange={handleImport} />
    </div>
  </Card>
</div>

{#if dirty}
  <FloatingActions onSave={save} onDiscard={discard} />
{/if}
