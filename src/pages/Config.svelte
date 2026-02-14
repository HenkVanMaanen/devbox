<script lang="ts">
  import { z } from 'zod';

  import type { GlobalConfig } from '$lib/types';

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
  import { globalConfigSchema, profilesSchema } from '$lib/types';
  import { clone } from '$lib/utils/storage';

  const importSchema = z.object({
    config: globalConfigSchema.partial(),
    defaultProfileId: z.string().optional(),
    exportedAt: z.string().optional(),
    hetznerToken: z.string().optional(),
    profiles: profilesSchema.optional(),
    serverTokens: z.record(z.string(), z.string()).optional(),
    theme: z.string().optional(),
  });

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
      config: configStore.value,
      defaultProfileId: profilesStore.defaultProfileId,
      exportedAt: new Date().toISOString(),
      hetznerToken: credentialsStore.token,
      profiles: profilesStore.profiles,
      serverTokens: serversStore.serverTokens,
      theme: themeStore.themeId,
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
        const parsed: unknown = JSON.parse(text);
        const result = importSchema.safeParse(parsed);

        if (!result.success) {
          const fieldErrors = result.error.issues.map((i) => i.path.join('.')).join(', ');
          toast.error(`Invalid config file: ${fieldErrors}`);
          return;
        }

        const data = result.data;

        // Import config (merge with defaults to handle missing fields)
        configStore.value = { ...configStore.value, ...data.config } as GlobalConfig;
        configStore.save();
        snapshot = clone(configStore.value);

        // Import profiles if present
        if (data.profiles) {
          for (const [id, profile] of Object.entries(data.profiles)) {
            if (!profilesStore.get(id)) {
              profilesStore.profiles[id] = profile;
            }
          }
          profilesStore.save();
        }

        if (data.defaultProfileId) {
          profilesStore.setDefault(data.defaultProfileId);
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
