<script lang="ts">
  import ServerCard from '$components/ServerCard.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Modal from '$components/ui/Modal.svelte';
  import * as hetzner from '$lib/api/hetzner';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { generateCloudInit } from '$lib/utils/cloudinit';
  import { generateServerName } from '$lib/utils/names';

  let deleteModal = $state({ open: false, server: null as null | { id: number; name: string } });
  let selectedProfileId = $state<null | string>(profilesStore.defaultProfileId);

  // Load servers and options on mount
  $effect(() => {
    if (credentialsStore.hasToken) {
      void serversStore.load(credentialsStore.token);
      void serversStore.loadOptions(credentialsStore.token);
    }
  });

  // Get merged config for selected profile
  const selectedConfig = $derived(profilesStore.getConfigForProfile(selectedProfileId));

  // Build configuration summary
  const configSummary = $derived.by(() => {
    const parts: string[] = [];
    const serverType = serversStore.serverTypes.find((t) => t.name === selectedConfig.hetzner.serverType);
    if (serverType) {
      parts.push(`${serverType.name} (${serverType.cores} vCPU, ${serverType.memory}GB RAM)`);
    }
    const location = serversStore.locations.find((l) => l.name === selectedConfig.hetzner.location);
    if (location) {
      parts.push(location.city);
    }
    // Add price estimation
    if (serverType && selectedConfig.hetzner.location) {
      const priceInfo = serverType.prices.find((p) => p.location === selectedConfig.hetzner.location);
      if (priceInfo) {
        const hourly = Number.parseFloat(priceInfo.price_hourly.gross);
        const monthly = Number.parseFloat(priceInfo.price_monthly.gross);
        parts.push(`€${hourly.toFixed(4)}/hr (~€${monthly.toFixed(2)}/mo)`);
      }
    }
    if (selectedConfig.chezmoi.repoUrl) {
      parts.push('chezmoi');
    }
    return parts.join(' • ');
  });

  async function createServer() {
    if (!credentialsStore.hasToken) {
      toast.error('Please configure your Hetzner API token first');
      window.location.hash = '#credentials';
      return;
    }

    const config = profilesStore.getConfigForProfile(selectedProfileId);
    const serverName = generateServerName();

    try {
      // Ensure SSH keys exist in Hetzner
      const sshKeyIds: number[] = [];
      for (const key of config.ssh.keys) {
        if (key.pubKey) {
          const safeName = key.name.replaceAll(/[^a-zA-Z0-9_-]/g, '-').replaceAll(/-+/g, '-') || 'key';
          const hetznerKey = await hetzner.ensureSSHKey(credentialsStore.token, `devbox-${safeName}`, key.pubKey);
          sshKeyIds.push(hetznerKey.id);
        }
      }

      // Generate cloud-init with current theme
      const userData = generateCloudInit(serverName, credentialsStore.token, config, {
        terminalColors: themeStore.theme.terminal,
        themeColors: themeStore.theme.colors,
      });

      // Create server
      await serversStore.create(
        credentialsStore.token,
        {
          image: config.hetzner.baseImage,
          labels: { managed: 'devbox', progress: 'provisioning' },
          location: config.hetzner.location,
          name: serverName,
          serverType: config.hetzner.serverType,
          sshKeys: sshKeyIds,
          userData,
        },
        config.services.accessToken,
      );

      toast.success('Server created successfully!');
    } catch (error) {
      toast.error(`Failed to create server: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async function confirmDelete() {
    if (!deleteModal.server) return;

    try {
      await serversStore.delete(credentialsStore.token, deleteModal.server.id, deleteModal.server.name);
      toast.success('Server deleted');
    } catch (error) {
      toast.error(`Failed to delete: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      deleteModal = { open: false, server: null };
    }
  }
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold">Dashboard</h1>
  </div>

  {#if credentialsStore.hasToken}
    <Card>
      <div class="space-y-4">
        <h2 class="text-lg font-semibold">Create New Devbox</h2>

        {#if profilesStore.profileList.length > 0}
          <div>
            <label for="profile-select" class="mb-1.5 block text-sm font-medium">Profile</label>
            <select
              id="profile-select"
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

        {#if configSummary}
          <div class="bg-muted/30 rounded-md p-4">
            <p class="mb-1 text-sm font-medium">Configuration Summary</p>
            <p class="text-muted-foreground text-sm">{configSummary}</p>
          </div>
        {/if}

        <Button onclick={createServer} loading={serversStore.creating} class="w-full">
          {serversStore.creating ? serversStore.createProgress : 'Create Server'}
        </Button>
      </div>
    </Card>
  {/if}

  {#if !credentialsStore.hasToken}
    <Card>
      <p class="text-muted-foreground">
        Please <a href="#credentials" class="text-primary hover:underline">configure your Hetzner API token</a> to get started.
      </p>
    </Card>
  {:else if serversStore.loading}
    <Card>
      <p class="text-muted-foreground">Loading servers...</p>
    </Card>
  {:else if serversStore.error}
    <Card>
      <p class="text-destructive">Error: {serversStore.error}</p>
      <Button variant="secondary" class="mt-4" onclick={() => serversStore.load(credentialsStore.token)}>Retry</Button>
    </Card>
  {:else if serversStore.devboxServers.length === 0}
    <Card>
      <p class="text-muted-foreground">No servers yet. Click "Create Server" to get started.</p>
    </Card>
  {:else}
    {#each serversStore.devboxServers as server (server.id)}
      <ServerCard
        {server}
        onDelete={() => (deleteModal = { open: true, server: { id: server.id, name: server.name } })}
      />
    {/each}
  {/if}
</div>

<Modal bind:open={deleteModal.open} title="Delete Server" onClose={() => (deleteModal = { open: false, server: null })}>
  <p>Are you sure you want to delete <strong>{deleteModal.server?.name}</strong>? This action cannot be undone.</p>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (deleteModal = { open: false, server: null })}>Cancel</Button>
    <Button variant="destructive" onclick={confirmDelete}>Delete</Button>
  {/snippet}
</Modal>
