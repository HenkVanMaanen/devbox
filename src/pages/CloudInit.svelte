<script lang="ts">
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { generateCloudInit } from '$lib/utils/cloudinit';

  let selectedProfileId = $state<null | string>(profilesStore.defaultProfileId);
  let refreshCounter = $state(0);

  // Generate cloud-init script (refreshCounter triggers regeneration with new access token)
  const script = $derived.by(() => {
    // Access refreshCounter to make this reactive to refresh button
    void refreshCounter;
    if (!credentialsStore.hasToken) return '';
    const config = profilesStore.getConfigForProfile(selectedProfileId);
    return generateCloudInit('devbox-preview', credentialsStore.token, config, {
      terminalColors: themeStore.theme.terminal,
      themeColors: themeStore.theme.colors,
    });
  });

  function refresh() {
    refreshCounter++;
    toast.success('Cloud-init refreshed with new access token');
  }

  // Calculate size
  const size = $derived(new Blob([script]).size);
  const sizeKB = $derived((size / 1024).toFixed(1));
  const sizePercent = $derived(Math.round((size / 32_768) * 100));
  const sizeColor = $derived(
    sizePercent > 90 ? 'text-destructive' : sizePercent > 70 ? 'text-warning' : 'text-success',
  );
  const barColor = $derived(sizePercent > 90 ? 'bg-destructive' : sizePercent > 70 ? 'bg-warning' : 'bg-success');

  async function copyToClipboard() {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- clipboard API may not be available
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(script);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = script;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.append(textarea);
        textarea.select();
        // eslint-disable-next-line @typescript-eslint/no-deprecated
        document.execCommand('copy');
        textarea.remove();
      }
      toast.success('Copied to clipboard');
    } catch {
      toast.error('Failed to copy');
    }
  }

  function download() {
    const blob = new Blob([script], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cloud-init.yaml';
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success('Downloaded cloud-init.yaml');
  }
</script>

<div class="space-y-6">
  <h1 class="text-2xl font-bold">Cloud-Init</h1>

  {#if !credentialsStore.hasToken}
    <Card>
      <div class="py-8 text-center">
        <h2 class="mb-2 text-lg font-semibold">Hetzner Token Required</h2>
        <p class="text-muted-foreground mb-4">Configure your Hetzner API token to preview cloud-init scripts.</p>
        <a
          href="#credentials"
          class="bg-primary text-primary-foreground hover:bg-primary-hover inline-flex items-center justify-center rounded-md px-4 py-2"
        >
          Configure API Token
        </a>
      </div>
    </Card>
  {:else}
    {#if profilesStore.profileList.length > 0}
      <div>
        <label for="cloudinit-profile" class="mb-1.5 block text-sm font-medium">Profile</label>
        <select
          id="cloudinit-profile"
          bind:value={selectedProfileId}
          class="bg-background border-border focus:ring-ring focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base transition-colors duration-150
                 focus:ring-2 focus:outline-none"
        >
          <option value={null}>Use global config (no profile)</option>
          {#each profilesStore.profileList as profile (profile.id)}
            <option value={profile.id}>
              {profile.id === profilesStore.defaultProfileId ? '★ ' : ''}{profile.name}
              {profile.id === profilesStore.defaultProfileId ? ' (Default)' : ''}
            </option>
          {/each}
        </select>
      </div>
    {/if}

    <Card>
      <div class="mb-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold">Generated Script</h2>
          <p class="text-muted-foreground text-sm">Preview the cloud-init user-data that will be sent to Hetzner</p>
        </div>
        <div class="flex gap-2">
          <Button variant="secondary" size="sm" onclick={refresh}>Refresh</Button>
          <Button variant="secondary" size="sm" onclick={copyToClipboard}>Copy</Button>
          <Button variant="secondary" size="sm" onclick={download}>Download</Button>
        </div>
      </div>

      <div class="mb-4">
        <div class="mb-1 flex items-center justify-between text-sm">
          <span>Size</span>
          <span class="{sizeColor} font-medium">{sizeKB} KB / 32 KB ({sizePercent}%)</span>
        </div>
        <div class="bg-muted h-2 overflow-hidden rounded-full">
          <div class="h-full {barColor} transition-all" style="width: {Math.min(sizePercent, 100)}%"></div>
        </div>
        {#if sizePercent > 90}
          <p class="text-destructive mt-1 text-xs">Warning: Close to Hetzner's 32KB limit!</p>
        {/if}
      </div>

      <div class="border-border overflow-hidden rounded-md border">
        <pre class="bg-background max-h-[70vh] overflow-auto p-4 font-mono text-xs leading-relaxed"><code>{script}</code
          ></pre>
      </div>
    </Card>
  {/if}
</div>
