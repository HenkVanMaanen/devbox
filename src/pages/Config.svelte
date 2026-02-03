<script lang="ts">
  import { configStore } from '$lib/stores/config.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';
  import type { GlobalConfig, Profiles } from '$lib/types';
  import Input from '$components/ui/Input.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import FloatingActions from '$components/FloatingActions.svelte';

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

  // SSH Key management
  let newSSHKeyName = $state('');
  let newSSHKeyPubKey = $state('');

  function addSSHKey() {
    if (!newSSHKeyPubKey.trim()) {
      toast.error('Please enter a public key');
      return;
    }

    // Auto-extract name from key comment if not provided
    let name = newSSHKeyName.trim();
    if (!name) {
      const parts = newSSHKeyPubKey.trim().split(' ');
      if (parts.length >= 3) {
        name = parts.slice(2).join(' ');
      }
    }
    if (!name) {
      name = `key-${configStore.value.ssh.keys.length + 1}`;
    }

    configStore.value.ssh.keys = [...configStore.value.ssh.keys, { name, pubKey: newSSHKeyPubKey.trim() }];
    newSSHKeyName = '';
    newSSHKeyPubKey = '';
  }

  function removeSSHKey(index: number) {
    configStore.value.ssh.keys = configStore.value.ssh.keys.filter((_, i) => i !== index);
  }

  // Git credential management
  let newGitHost = $state('');
  let newGitUsername = $state('');
  let newGitToken = $state('');

  function addGitCredential() {
    if (!newGitHost.trim() || !newGitUsername.trim() || !newGitToken.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    configStore.value.git.credentials = [
      ...configStore.value.git.credentials,
      { host: newGitHost.trim(), username: newGitUsername.trim(), token: newGitToken.trim() },
    ];
    newGitHost = '';
    newGitUsername = '';
    newGitToken = '';
  }

  function removeGitCredential(index: number) {
    configStore.value.git.credentials = configStore.value.git.credentials.filter((_, i) => i !== index);
  }

  // Export configuration
  let fileInputRef: HTMLInputElement | undefined = $state();

  function exportConfig() {
    const exportData = {
      version: 1,
      exportedAt: new Date().toISOString(),
      config: configStore.value,
      profiles: profilesStore.profiles,
      defaultProfileId: profilesStore.defaultProfileId,
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

        if (!data.config) {
          toast.error('Invalid config file: missing config');
          return;
        }

        // Import config
        configStore.value = data.config as GlobalConfig;
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

        // Set default profile if present
        if (data.defaultProfileId) {
          profilesStore.setDefault(data.defaultProfileId);
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

  <Card title="Git Settings">
    <div class="space-y-4">
      <Input label="User Name" bind:value={configStore.value.git.userName} placeholder="John Doe" />
      <Input label="Email" type="email" bind:value={configStore.value.git.userEmail} placeholder="john@example.com" />
    </div>
  </Card>

  <Card title="SSH Keys">
    {#if configStore.value.ssh.keys.length > 0}
      <div class="space-y-2 mb-4">
        {#each configStore.value.ssh.keys as key, i}
          <div class="flex items-center justify-between p-3 bg-muted rounded-md">
            <div>
              <p class="font-medium">{key.name}</p>
              <p class="text-sm text-muted-foreground font-mono truncate max-w-md">{key.pubKey.slice(0, 50)}...</p>
            </div>
            <Button variant="ghost" size="sm" onclick={() => removeSSHKey(i)}>Remove</Button>
          </div>
        {/each}
      </div>
    {/if}

    <div class="space-y-3 p-4 border border-border rounded-md">
      <Input label="Name (optional)" bind:value={newSSHKeyName} placeholder="my-key" />
      <div class="field">
        <label for="ssh-pubkey" class="block text-sm font-medium mb-1.5">Public Key</label>
        <textarea
          id="ssh-pubkey"
          bind:value={newSSHKeyPubKey}
          class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 placeholder:text-placeholder resize-y font-mono text-sm"
          placeholder="ssh-ed25519 AAAA..."
        ></textarea>
      </div>
      <Button variant="secondary" onclick={addSSHKey}>Add SSH Key</Button>
    </div>
  </Card>

  <Card title="Git Credentials">
    {#if configStore.value.git.credentials.length > 0}
      <div class="space-y-2 mb-4">
        {#each configStore.value.git.credentials as cred, i}
          <div class="flex items-center justify-between p-3 bg-muted rounded-md">
            <div>
              <p class="font-medium">{cred.host}</p>
              <p class="text-sm text-muted-foreground">{cred.username}</p>
            </div>
            <Button variant="ghost" size="sm" onclick={() => removeGitCredential(i)}>Remove</Button>
          </div>
        {/each}
      </div>
    {/if}

    <div class="space-y-3 p-4 border border-border rounded-md">
      <Input label="Host" bind:value={newGitHost} placeholder="github.com" />
      <Input label="Username" bind:value={newGitUsername} placeholder="username" />
      <Input label="Token" type="password" bind:value={newGitToken} placeholder="ghp_..." />
      <Button variant="secondary" onclick={addGitCredential}>Add Credential</Button>
    </div>
  </Card>

  <Card title="Hetzner Settings">
    <div class="space-y-4">
      <div class="field">
        <label for="hetzner-server-type" class="block text-sm font-medium mb-1.5">Server Type</label>
        <select
          id="hetzner-server-type"
          bind:value={configStore.value.hetzner.serverType}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#if serversStore.serverTypes.length === 0}
            <option value={configStore.value.hetzner.serverType}>{configStore.value.hetzner.serverType}</option>
          {:else}
            {#each serversStore.serverTypes as type}
              <option value={type.name}>{type.name} - {type.cores} vCPU, {type.memory}GB RAM</option>
            {/each}
          {/if}
        </select>
      </div>

      <div class="field">
        <label for="hetzner-location" class="block text-sm font-medium mb-1.5">Location</label>
        <select
          id="hetzner-location"
          bind:value={configStore.value.hetzner.location}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#if serversStore.locations.length === 0}
            <option value={configStore.value.hetzner.location}>{configStore.value.hetzner.location}</option>
          {:else}
            {#each serversStore.locations as loc}
              <option value={loc.name}>{loc.name} - {loc.city}, {loc.country}</option>
            {/each}
          {/if}
        </select>
      </div>

      <div class="field">
        <label for="hetzner-image" class="block text-sm font-medium mb-1.5">Base Image</label>
        <select
          id="hetzner-image"
          bind:value={configStore.value.hetzner.baseImage}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#if serversStore.images.length === 0}
            <option value={configStore.value.hetzner.baseImage}>{configStore.value.hetzner.baseImage}</option>
          {:else}
            {#each serversStore.images as img}
              <option value={img.name}>{img.description}</option>
            {/each}
          {/if}
        </select>
      </div>
    </div>
  </Card>

  <Card title="Shell">
    <label class="flex items-center gap-3 cursor-pointer">
      <input
        type="checkbox"
        bind:checked={configStore.value.shell.starship}
        class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <span>Enable Starship prompt</span>
    </label>
  </Card>

  <Card title="Services">
    <div class="space-y-4">
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={configStore.value.services.codeServer} class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer" />
        <span>VS Code Server</span>
      </label>
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={configStore.value.services.claudeTerminal} class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer" />
        <span>Claude Terminal</span>
      </label>
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={configStore.value.services.shellTerminal} class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer" />
        <span>Shell Terminal</span>
      </label>
      <Input label="ACME Email" type="email" bind:value={configStore.value.services.acmeEmail} help="For Let's Encrypt certificates" />
    </div>
  </Card>

  <Card title="Auto-Delete">
    <div class="space-y-4">
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={configStore.value.autoDelete.enabled} class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer" />
        <span>Enable auto-delete for idle servers</span>
      </label>
      <Input label="Timeout (minutes)" type="number" bind:value={configStore.value.autoDelete.timeoutMinutes} />
      <Input label="Warning (minutes before)" type="number" bind:value={configStore.value.autoDelete.warningMinutes} />
    </div>
  </Card>

  <Card title="Claude Code">
    <div class="space-y-4">
      <Input label="API Key" type="password" bind:value={configStore.value.claude.apiKey} />
      <div class="field">
        <label for="claude-settings" class="block text-sm font-medium mb-1.5">Settings JSON</label>
        <textarea
          id="claude-settings"
          bind:value={configStore.value.claude.settings}
          class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 placeholder:text-placeholder resize-y font-mono text-sm"
          placeholder={'{"theme": "dark"}'}
        ></textarea>
      </div>
    </div>
  </Card>

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
