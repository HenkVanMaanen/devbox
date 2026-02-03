<script lang="ts">
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { generateCloudInit } from '$lib/utils/cloudinit';
  import { generateServerName } from '$lib/utils/names';
  import * as hetzner from '$lib/api/hetzner';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Modal from '$components/ui/Modal.svelte';
  import ServerCard from '$components/ServerCard.svelte';

  let deleteModal = $state({ open: false, server: null as { id: number; name: string } | null });
  let selectedProfileId = $state<string | null>(profilesStore.defaultProfileId);

  // Load servers and options on mount
  $effect(() => {
    if (credentialsStore.hasToken) {
      serversStore.load(credentialsStore.token);
      serversStore.loadOptions(credentialsStore.token);
    }
  });

  // Get merged config for selected profile
  const selectedConfig = $derived(profilesStore.getConfigForProfile(selectedProfileId));

  // Build configuration summary
  const configSummary = $derived.by(() => {
    const parts: string[] = [];
    const serverType = serversStore.serverTypes.find(t => t.name === selectedConfig.hetzner.serverType);
    if (serverType) {
      parts.push(`${serverType.name} (${serverType.cores} vCPU, ${serverType.memory}GB RAM)`);
    }
    const location = serversStore.locations.find(l => l.name === selectedConfig.hetzner.location);
    if (location) {
      parts.push(location.city);
    }
    if (selectedConfig.packages.mise?.length) {
      const misePackages = selectedConfig.packages.mise.slice(0, 3).join(', ');
      parts.push(misePackages + (selectedConfig.packages.mise.length > 3 ? '...' : ''));
    }
    if (selectedConfig.repos?.length) {
      parts.push(`${selectedConfig.repos.length} repo(s)`);
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
          const safeName = key.name.replace(/[^a-zA-Z0-9_-]/g, '-').replace(/-+/g, '-') || 'key';
          const hetznerKey = await hetzner.ensureSSHKey(
            credentialsStore.token,
            `devbox-${safeName}`,
            key.pubKey
          );
          sshKeyIds.push(hetznerKey.id);
        }
      }

      // Generate cloud-init
      const userData = generateCloudInit(serverName, credentialsStore.token, config);

      // Create server
      await serversStore.create(
        credentialsStore.token,
        {
          name: serverName,
          serverType: config.hetzner.serverType,
          image: config.hetzner.baseImage,
          location: config.hetzner.location,
          sshKeys: sshKeyIds,
          userData,
          labels: { managed: 'devbox' },
        },
        config.services.accessToken
      );

      toast.success('Server created successfully!');
    } catch (e) {
      toast.error(`Failed to create server: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  }

  async function confirmDelete() {
    if (!deleteModal.server) return;

    try {
      await serversStore.delete(credentialsStore.token, deleteModal.server.id, deleteModal.server.name);
      toast.success('Server deleted');
    } catch (e) {
      toast.error(`Failed to delete: ${e instanceof Error ? e.message : 'Unknown error'}`);
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
            <label for="profile-select" class="block text-sm font-medium mb-1.5">Profile</label>
            <select
              id="profile-select"
              bind:value={selectedProfileId}
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-2 focus:ring-ring focus:border-primary
                     transition-colors duration-150"
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
            <p class="text-sm font-medium mb-1">Configuration Summary</p>
            <p class="text-sm text-muted-foreground">{configSummary}</p>
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
      <Button variant="secondary" class="mt-4" onclick={() => serversStore.load(credentialsStore.token)}>
        Retry
      </Button>
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

<Modal
  bind:open={deleteModal.open}
  title="Delete Server"
  onClose={() => (deleteModal = { open: false, server: null })}
>
  <p>Are you sure you want to delete <strong>{deleteModal.server?.name}</strong>? This action cannot be undone.</p>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (deleteModal = { open: false, server: null })}>
      Cancel
    </Button>
    <Button variant="destructive" onclick={confirmDelete}>
      Delete
    </Button>
  {/snippet}
</Modal>
