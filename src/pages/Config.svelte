<script lang="ts">
  import { configStore } from '$lib/stores/config.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';
  import { validateSSHKey, extractSSHKeyName } from '$lib/utils/validation';
  import { getMiseToolOptions, getAptPackageOptions, APT_CATEGORY_LABELS } from '$lib/data/packages';
  import type { GlobalConfig, Profiles, SSHKey, GitCredential } from '$lib/types';
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
  let sshKeyError = $state('');

  // Validate SSH key on input
  $effect(() => {
    if (newSSHKeyPubKey.trim()) {
      const result = validateSSHKey(newSSHKeyPubKey);
      sshKeyError = result.error ?? '';
    } else {
      sshKeyError = '';
    }
  });

  function addSSHKey() {
    if (!newSSHKeyPubKey.trim()) {
      toast.error('Please enter a public key');
      return;
    }

    // Validate the SSH key
    const validation = validateSSHKey(newSSHKeyPubKey);
    if (!validation.valid) {
      toast.error(validation.error ?? 'Invalid SSH key');
      return;
    }

    // Auto-extract name from key comment if not provided
    let name = newSSHKeyName.trim();
    if (!name) {
      name = extractSSHKeyName(newSSHKeyPubKey) ?? '';
    }
    if (!name) {
      name = `key-${configStore.value.ssh.keys.length + 1}`;
    }

    configStore.value.ssh.keys = [...configStore.value.ssh.keys, { name, pubKey: newSSHKeyPubKey.trim() }];
    newSSHKeyName = '';
    newSSHKeyPubKey = '';
    sshKeyError = '';
    toast.success(`SSH key "${name}" added`);
  }

  function removeSSHKey(index: number) {
    configStore.value.ssh.keys = configStore.value.ssh.keys.filter((_, i) => i !== index);
  }

  // SSH Key editing
  let editingSSHKeyIndex = $state<number | null>(null);
  let editSSHKeyName = $state('');
  let editSSHKeyPubKey = $state('');
  let editSSHKeyError = $state('');

  function startEditSSHKey(index: number) {
    const key = configStore.value.ssh.keys[index];
    if (!key) return;
    editingSSHKeyIndex = index;
    editSSHKeyName = key.name;
    editSSHKeyPubKey = key.pubKey;
    editSSHKeyError = '';
  }

  function cancelEditSSHKey() {
    editingSSHKeyIndex = null;
    editSSHKeyName = '';
    editSSHKeyPubKey = '';
    editSSHKeyError = '';
  }

  function saveEditSSHKey() {
    if (editingSSHKeyIndex === null) return;

    const validation = validateSSHKey(editSSHKeyPubKey);
    if (!validation.valid) {
      editSSHKeyError = validation.error ?? 'Invalid SSH key';
      return;
    }

    let name = editSSHKeyName.trim();
    if (!name) {
      name = extractSSHKeyName(editSSHKeyPubKey) ?? `key-${editingSSHKeyIndex + 1}`;
    }

    configStore.value.ssh.keys[editingSSHKeyIndex] = { name, pubKey: editSSHKeyPubKey.trim() };
    configStore.value.ssh.keys = [...configStore.value.ssh.keys]; // Trigger reactivity
    cancelEditSSHKey();
    toast.success('SSH key updated');
  }

  // Validate SSH key on edit
  $effect(() => {
    if (editingSSHKeyIndex !== null && editSSHKeyPubKey.trim()) {
      const result = validateSSHKey(editSSHKeyPubKey);
      editSSHKeyError = result.error ?? '';
    }
  });

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

  // Git credential editing
  let editingGitCredIndex = $state<number | null>(null);
  let editGitHost = $state('');
  let editGitUsername = $state('');
  let editGitToken = $state('');

  function startEditGitCredential(index: number) {
    const cred = configStore.value.git.credentials[index];
    if (!cred) return;
    editingGitCredIndex = index;
    editGitHost = cred.host;
    editGitUsername = cred.username;
    editGitToken = cred.token;
  }

  function cancelEditGitCredential() {
    editingGitCredIndex = null;
    editGitHost = '';
    editGitUsername = '';
    editGitToken = '';
  }

  function saveEditGitCredential() {
    if (editingGitCredIndex === null) return;
    if (!editGitHost.trim() || !editGitUsername.trim() || !editGitToken.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    configStore.value.git.credentials[editingGitCredIndex] = {
      host: editGitHost.trim(),
      username: editGitUsername.trim(),
      token: editGitToken.trim(),
    };
    configStore.value.git.credentials = [...configStore.value.git.credentials];
    cancelEditGitCredential();
    toast.success('Git credential updated');
  }

  // Repository management
  let newRepo = $state('');

  function addRepo() {
    if (!newRepo.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }
    configStore.value.repos = [...configStore.value.repos, newRepo.trim()];
    newRepo = '';
  }

  function removeRepo(index: number) {
    configStore.value.repos = configStore.value.repos.filter((_, i) => i !== index);
  }

  // Repo editing
  let editingRepoIndex = $state<number | null>(null);
  let editRepoUrl = $state('');

  function startEditRepo(index: number) {
    const repo = configStore.value.repos[index];
    if (!repo) return;
    editingRepoIndex = index;
    editRepoUrl = repo;
  }

  function cancelEditRepo() {
    editingRepoIndex = null;
    editRepoUrl = '';
  }

  function saveEditRepo() {
    if (editingRepoIndex === null) return;
    if (!editRepoUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }

    configStore.value.repos[editingRepoIndex] = editRepoUrl.trim();
    configStore.value.repos = [...configStore.value.repos];
    cancelEditRepo();
    toast.success('Repository updated');
  }

  // Package management
  let miseToolFilter = $state('');
  let aptPackageFilter = $state('');
  let customMiseTool = $state('');
  let customAptPackage = $state('');

  const miseOptions = getMiseToolOptions();
  const aptOptions = getAptPackageOptions();

  let filteredMiseOptions = $derived(
    miseToolFilter
      ? miseOptions.filter(
          (o) => o.value.toLowerCase().includes(miseToolFilter.toLowerCase()) || o.description.toLowerCase().includes(miseToolFilter.toLowerCase())
        )
      : miseOptions
  );

  let filteredAptOptions = $derived(
    aptPackageFilter
      ? aptOptions.filter(
          (o) =>
            o.value.toLowerCase().includes(aptPackageFilter.toLowerCase()) || o.description.toLowerCase().includes(aptPackageFilter.toLowerCase())
        )
      : aptOptions
  );

  function toggleMiseTool(tool: string) {
    if (configStore.value.packages.mise.includes(tool)) {
      configStore.value.packages.mise = configStore.value.packages.mise.filter((t) => t !== tool);
    } else {
      configStore.value.packages.mise = [...configStore.value.packages.mise, tool];
    }
  }

  function toggleAptPackage(pkg: string) {
    if (configStore.value.packages.apt.includes(pkg)) {
      configStore.value.packages.apt = configStore.value.packages.apt.filter((p) => p !== pkg);
    } else {
      configStore.value.packages.apt = [...configStore.value.packages.apt, pkg];
    }
  }

  function addCustomMiseTool() {
    if (!customMiseTool.trim()) return;
    if (!configStore.value.packages.mise.includes(customMiseTool.trim())) {
      configStore.value.packages.mise = [...configStore.value.packages.mise, customMiseTool.trim()];
    }
    customMiseTool = '';
  }

  function addCustomAptPackage() {
    if (!customAptPackage.trim()) return;
    if (!configStore.value.packages.apt.includes(customAptPackage.trim())) {
      configStore.value.packages.apt = [...configStore.value.packages.apt, customAptPackage.trim()];
    }
    customAptPackage = '';
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
        const importedConfig = data.config || data.globalConfig;
        if (!importedConfig) {
          toast.error('Invalid config file: missing config or globalConfig');
          return;
        }

        // Import config (merge with defaults to handle missing fields)
        configStore.value = { ...configStore.value, ...importedConfig } as GlobalConfig;
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

  // ACME provider options
  const acmeProviders = [
    { value: 'zerossl', label: 'ZeroSSL', description: 'No rate limits, recommended for testing' },
    { value: 'letsencrypt', label: "Let's Encrypt", description: 'Most popular CA' },
    { value: 'buypass', label: 'Buypass', description: 'Norwegian CA' },
    { value: 'actalis', label: 'Actalis', description: 'Italian CA' },
    { value: 'custom', label: 'Custom ACME', description: 'Self-hosted or other CA' },
  ];

  const dnsServices = [
    { value: 'sslip.io', label: 'sslip.io', description: 'Wildcard DNS for any IP' },
    { value: 'nip.io', label: 'nip.io', description: 'Dead simple wildcard DNS' },
  ];

  const shellOptions = [
    { value: 'fish', label: 'Fish', description: 'Modern, user-friendly shell' },
    { value: 'zsh', label: 'Zsh', description: 'Extended Bourne shell' },
    { value: 'bash', label: 'Bash', description: 'GNU Bourne-Again shell' },
  ];

  const claudeThemes = [
    { value: '', label: 'Default', description: 'System default' },
    { value: 'dark', label: 'Dark', description: 'Dark theme' },
    { value: 'light', label: 'Light', description: 'Light theme' },
    { value: 'dark-daltonized', label: 'Dark (Daltonized)', description: 'Color blind friendly dark' },
    { value: 'light-daltonized', label: 'Light (Daltonized)', description: 'Color blind friendly light' },
  ];

  // Claude credentials.json upload
  let claudeCredentialsInputRef: HTMLInputElement | undefined = $state();

  function triggerClaudeCredentialsUpload() {
    claudeCredentialsInputRef?.click();
  }

  function handleClaudeCredentialsUpload(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const credentials = JSON.parse(e.target?.result as string);
        configStore.value.claude.credentialsJson = credentials;
        toast.success('Claude credentials imported');
      } catch {
        toast.error('Invalid JSON file');
      }
    };
    reader.readAsText(file);
    input.value = ''; // Reset for re-upload
  }

  function clearClaudeCredentials() {
    configStore.value.claude.credentialsJson = null;
    toast.success('Claude credentials cleared');
  }

  // Helper to extract account info from credentials
  function getClaudeAccountInfo(credentials: Record<string, unknown> | null): { email?: string; org?: string; expires?: string; isExpired?: boolean } | null {
    if (!credentials) return null;

    const oauth = credentials.claudeAiOauth as Record<string, unknown> | undefined;
    if (!oauth) return null;

    const result: { email?: string; org?: string; expires?: string; isExpired?: boolean } = {};

    if (oauth.email) result.email = String(oauth.email);
    if (oauth.organizationName) result.org = String(oauth.organizationName);
    if (oauth.expiresAt) {
      const expiry = new Date(String(oauth.expiresAt));
      result.expires = expiry.toLocaleDateString();
      result.isExpired = expiry < new Date();
    }

    return Object.keys(result).length > 0 ? result : null;
  }

  const claudeAccountInfo = $derived(getClaudeAccountInfo(configStore.value.claude.credentialsJson));
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
          {#if editingSSHKeyIndex === i}
            <div class="p-3 bg-muted rounded-md space-y-3">
              <Input label="Name" bind:value={editSSHKeyName} placeholder="my-key" />
              <div class="field">
                <label for="edit-ssh-pubkey" class="block text-sm font-medium mb-1.5">Public Key</label>
                <textarea
                  id="edit-ssh-pubkey"
                  bind:value={editSSHKeyPubKey}
                  class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 rounded-md
                         focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                         placeholder:text-placeholder resize-y font-mono text-sm
                         {editSSHKeyError ? 'border-destructive' : 'border-border'}"
                  placeholder="ssh-ed25519 AAAA..."
                ></textarea>
                {#if editSSHKeyError}
                  <p class="text-sm text-destructive mt-1">{editSSHKeyError}</p>
                {/if}
              </div>
              <div class="flex gap-2">
                <Button variant="secondary" size="sm" onclick={saveEditSSHKey}>Save</Button>
                <Button variant="ghost" size="sm" onclick={cancelEditSSHKey}>Cancel</Button>
              </div>
            </div>
          {:else}
            <div class="flex items-center justify-between p-3 bg-muted rounded-md">
              <div>
                <p class="font-medium">{key.name}</p>
                <p class="text-sm text-muted-foreground font-mono truncate max-w-md">{key.pubKey.slice(0, 50)}...</p>
              </div>
              <div class="flex gap-2">
                <Button variant="ghost" size="sm" onclick={() => startEditSSHKey(i)}>Edit</Button>
                <Button variant="ghost" size="sm" onclick={() => removeSSHKey(i)}>Remove</Button>
              </div>
            </div>
          {/if}
        {/each}
      </div>
    {/if}

    <div class="space-y-3 p-4 border border-border rounded-md">
      <Input label="Name (optional)" bind:value={newSSHKeyName} placeholder="my-key" help="Auto-extracted from key comment if empty" />
      <div class="field">
        <label for="ssh-pubkey" class="block text-sm font-medium mb-1.5">Public Key</label>
        <textarea
          id="ssh-pubkey"
          bind:value={newSSHKeyPubKey}
          class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 placeholder:text-placeholder resize-y font-mono text-sm
                 {sshKeyError ? 'border-destructive' : 'border-border'}"
          placeholder="ssh-ed25519 AAAA..."
          aria-invalid={sshKeyError ? 'true' : undefined}
        ></textarea>
        {#if sshKeyError}
          <p class="text-sm text-destructive mt-1">{sshKeyError}</p>
        {/if}
      </div>
      <Button variant="secondary" onclick={addSSHKey}>Add SSH Key</Button>
    </div>
  </Card>

  <Card title="Git Credentials">
    {#if configStore.value.git.credentials.length > 0}
      <div class="space-y-2 mb-4">
        {#each configStore.value.git.credentials as cred, i}
          {#if editingGitCredIndex === i}
            <div class="p-3 bg-muted rounded-md space-y-3">
              <Input label="Host" bind:value={editGitHost} placeholder="github.com" />
              <Input label="Username" bind:value={editGitUsername} placeholder="username" />
              <Input label="Token" type="password" bind:value={editGitToken} placeholder="ghp_..." />
              <div class="flex gap-2">
                <Button variant="secondary" size="sm" onclick={saveEditGitCredential}>Save</Button>
                <Button variant="ghost" size="sm" onclick={cancelEditGitCredential}>Cancel</Button>
              </div>
            </div>
          {:else}
            <div class="flex items-center justify-between p-3 bg-muted rounded-md">
              <div>
                <p class="font-medium">{cred.host}</p>
                <p class="text-sm text-muted-foreground">{cred.username}</p>
              </div>
              <div class="flex gap-2">
                <Button variant="ghost" size="sm" onclick={() => startEditGitCredential(i)}>Edit</Button>
                <Button variant="ghost" size="sm" onclick={() => removeGitCredential(i)}>Remove</Button>
              </div>
            </div>
          {/if}
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

  <Card title="Repositories">
    <p class="text-sm text-muted-foreground mb-4">Repositories to automatically clone when creating a new devbox.</p>
    {#if configStore.value.repos.length > 0}
      <div class="space-y-2 mb-4">
        {#each configStore.value.repos as repo, i}
          {#if editingRepoIndex === i}
            <div class="p-3 bg-muted rounded-md space-y-3">
              <input
                type="text"
                bind:value={editRepoUrl}
                placeholder="https://github.com/user/repo.git"
                class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                       focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary font-mono text-sm"
              />
              <div class="flex gap-2">
                <Button variant="secondary" size="sm" onclick={saveEditRepo}>Save</Button>
                <Button variant="ghost" size="sm" onclick={cancelEditRepo}>Cancel</Button>
              </div>
            </div>
          {:else}
            <div class="flex items-center justify-between p-3 bg-muted rounded-md">
              <p class="text-sm font-mono truncate flex-1">{repo}</p>
              <div class="flex gap-2">
                <Button variant="ghost" size="sm" onclick={() => startEditRepo(i)}>Edit</Button>
                <Button variant="ghost" size="sm" onclick={() => removeRepo(i)}>Remove</Button>
              </div>
            </div>
          {/if}
        {/each}
      </div>
    {/if}

    <div class="flex gap-2">
      <input
        type="text"
        bind:value={newRepo}
        placeholder="https://github.com/user/repo.git"
        class="flex-1 min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
               focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
      />
      <Button variant="secondary" onclick={addRepo}>Add</Button>
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
    <div class="space-y-4">
      <div class="field">
        <label for="shell-default" class="block text-sm font-medium mb-1.5">Default Shell</label>
        <select
          id="shell-default"
          bind:value={configStore.value.shell.default}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#each shellOptions as shell}
            <option value={shell.value}>{shell.label} - {shell.description}</option>
          {/each}
        </select>
      </div>

      <label class="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          bind:checked={configStore.value.shell.starship}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
        <span>Enable Starship prompt</span>
      </label>
    </div>
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

      <div class="field">
        <label for="dns-service" class="block text-sm font-medium mb-1.5">DNS Service</label>
        <select
          id="dns-service"
          bind:value={configStore.value.services.dnsService}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#each dnsServices as dns}
            <option value={dns.value}>{dns.label} - {dns.description}</option>
          {/each}
        </select>
      </div>

      <div class="field">
        <label for="acme-provider" class="block text-sm font-medium mb-1.5">ACME Provider</label>
        <select
          id="acme-provider"
          bind:value={configStore.value.services.acmeProvider}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#each acmeProviders as provider}
            <option value={provider.value}>{provider.label} - {provider.description}</option>
          {/each}
        </select>
      </div>

      <Input label="ACME Email (optional)" type="email" bind:value={configStore.value.services.acmeEmail} help="For Let's Encrypt certificates" />

      {#if configStore.value.services.acmeProvider === 'zerossl'}
        <div class="bg-muted/30 rounded-md p-4 space-y-4">
          <Input
            label="ZeroSSL EAB Key ID"
            bind:value={configStore.value.services.zerosslEabKeyId}
            placeholder="From zerossl.com/acme"
            help="External Account Binding Key ID from ZeroSSL"
          />
          <Input
            label="ZeroSSL EAB HMAC Key"
            type="password"
            bind:value={configStore.value.services.zerosslEabKey}
            placeholder="From zerossl.com/acme"
            help="External Account Binding HMAC Key from ZeroSSL"
          />
        </div>
      {/if}

      {#if configStore.value.services.acmeProvider === 'actalis'}
        <div class="bg-muted/30 rounded-md p-4 space-y-4">
          <Input label="Actalis EAB Key ID" bind:value={configStore.value.services.actalisEabKeyId} placeholder="From Actalis ACME dashboard" />
          <Input label="Actalis EAB HMAC Key" type="password" bind:value={configStore.value.services.actalisEabKey} placeholder="From Actalis ACME dashboard" />
        </div>
      {/if}

      {#if configStore.value.services.acmeProvider === 'custom'}
        <div class="bg-muted/30 rounded-md p-4 space-y-4">
          <Input label="Custom ACME Directory URL" type="url" bind:value={configStore.value.services.customAcmeUrl} placeholder="https://acme.example.com/directory" />
          <Input label="EAB Key ID (optional)" bind:value={configStore.value.services.customEabKeyId} placeholder="Leave empty if not required" />
          <Input label="EAB HMAC Key (optional)" type="password" bind:value={configStore.value.services.customEabKey} placeholder="Leave empty if not required" />
        </div>
      {/if}
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

  <Card title="Packages - Mise Tools">
    <p class="text-sm text-muted-foreground mb-4">Select runtime tools to install via mise.</p>

    {#if configStore.value.packages.mise.length > 0}
      <div class="flex flex-wrap gap-2 mb-4">
        {#each configStore.value.packages.mise as tool}
          <span class="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded-md text-sm">
            {tool}
            <button type="button" onclick={() => toggleMiseTool(tool)} class="hover:text-destructive">&times;</button>
          </span>
        {/each}
      </div>
    {/if}

    <input
      type="text"
      bind:value={miseToolFilter}
      placeholder="Search tools..."
      class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md mb-3
             focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
    />

    <div class="max-h-48 overflow-y-auto border border-border rounded-md">
      {#each filteredMiseOptions.slice(0, 30) as option}
        <label class="flex items-center gap-3 px-3 py-2 hover:bg-muted cursor-pointer border-b border-border last:border-b-0">
          <input
            type="checkbox"
            checked={configStore.value.packages.mise.includes(option.value)}
            onchange={() => toggleMiseTool(option.value)}
            class="w-4 h-4 rounded border-2 border-border text-primary focus:ring-2 focus:ring-focus bg-background cursor-pointer"
          />
          <span class="flex-1">
            <span class="font-medium">{option.value}</span>
            <span class="text-sm text-muted-foreground ml-2">{option.description}</span>
          </span>
        </label>
      {/each}
    </div>

    <div class="mt-3 flex gap-2">
      <input
        type="text"
        bind:value={customMiseTool}
        placeholder="tool@version (e.g., elixir@1.16)"
        class="flex-1 min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
               focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
      />
      <Button variant="secondary" onclick={addCustomMiseTool}>Add</Button>
    </div>
    <p class="text-xs text-muted-foreground mt-1">
      Add any tool from <a href="https://mise.jdx.dev/plugins.html" target="_blank" class="text-primary hover:underline">mise plugins</a>
    </p>
  </Card>

  <Card title="Packages - APT">
    <p class="text-sm text-muted-foreground mb-4">Select system packages to install via apt.</p>

    {#if configStore.value.packages.apt.length > 0}
      <div class="flex flex-wrap gap-2 mb-4">
        {#each configStore.value.packages.apt as pkg}
          <span class="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded-md text-sm">
            {pkg}
            <button type="button" onclick={() => toggleAptPackage(pkg)} class="hover:text-destructive">&times;</button>
          </span>
        {/each}
      </div>
    {/if}

    <input
      type="text"
      bind:value={aptPackageFilter}
      placeholder="Search packages..."
      class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md mb-3
             focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
    />

    <div class="max-h-48 overflow-y-auto border border-border rounded-md">
      {#each filteredAptOptions.slice(0, 30) as option}
        <label class="flex items-center gap-3 px-3 py-2 hover:bg-muted cursor-pointer border-b border-border last:border-b-0">
          <input
            type="checkbox"
            checked={configStore.value.packages.apt.includes(option.value)}
            onchange={() => toggleAptPackage(option.value)}
            class="w-4 h-4 rounded border-2 border-border text-primary focus:ring-2 focus:ring-focus bg-background cursor-pointer"
          />
          <span class="flex-1">
            <span class="font-medium">{option.value}</span>
            <span class="text-sm text-muted-foreground ml-2">{option.description}</span>
          </span>
        </label>
      {/each}
    </div>

    <div class="mt-3 flex gap-2">
      <input
        type="text"
        bind:value={customAptPackage}
        placeholder="package-name (e.g., nginx)"
        class="flex-1 min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
               focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
      />
      <Button variant="secondary" onclick={addCustomAptPackage}>Add</Button>
    </div>
    <p class="text-xs text-muted-foreground mt-1">Add any package available in APT repositories</p>
  </Card>

  <Card title="Claude Code">
    <div class="space-y-4">
      <!-- Credentials.json upload -->
      <div class="field">
        <span class="block text-sm font-medium mb-1.5">Credentials File</span>
        <div class="flex items-center gap-2">
          <Button variant="secondary" onclick={triggerClaudeCredentialsUpload}>
            Upload credentials.json
          </Button>
          {#if configStore.value.claude.credentialsJson}
            <Button variant="destructive" size="sm" onclick={clearClaudeCredentials}>
              Clear
            </Button>
          {/if}
          <input
            bind:this={claudeCredentialsInputRef}
            type="file"
            accept=".json"
            class="hidden"
            onchange={handleClaudeCredentialsUpload}
          />
        </div>
        {#if configStore.value.claude.credentialsJson}
          <div class="bg-muted/30 rounded-md p-3 mt-2">
            <div class="text-sm flex items-center gap-2">
              <span class="text-success">✓</span>
              <span>Credentials loaded</span>
            </div>
            {#if claudeAccountInfo}
              <div class="text-sm text-muted-foreground mt-1 space-y-0.5">
                {#if claudeAccountInfo.email}
                  <div><span class="text-muted-foreground">Account:</span> {claudeAccountInfo.email}</div>
                {/if}
                {#if claudeAccountInfo.org}
                  <div><span class="text-muted-foreground">Org:</span> {claudeAccountInfo.org}</div>
                {/if}
                {#if claudeAccountInfo.expires}
                  <div>
                    <span class="text-muted-foreground">Expires:</span>
                    <span class={claudeAccountInfo.isExpired ? 'text-destructive' : ''}>{claudeAccountInfo.expires}</span>
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/if}
        <p class="text-xs text-muted-foreground mt-1">Upload your ~/.claude/credentials.json file, or enter API key manually below</p>
      </div>

      <Input label="API Key" type="password" bind:value={configStore.value.claude.apiKey} help="Your Anthropic API key (only needed if not using credentials.json)" />

      <div class="field">
        <label for="claude-theme" class="block text-sm font-medium mb-1.5">Theme</label>
        <select
          id="claude-theme"
          bind:value={configStore.value.claude.theme}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        >
          {#each claudeThemes as theme}
            <option value={theme.value}>{theme.label} - {theme.description}</option>
          {/each}
        </select>
      </div>

      <label class="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          bind:checked={configStore.value.claude.skipPermissions}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
        <span>Enable --dangerously-skip-permissions flag</span>
      </label>

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
