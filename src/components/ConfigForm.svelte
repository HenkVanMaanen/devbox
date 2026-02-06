<script lang="ts">
  import { serversStore } from '$lib/stores/servers.svelte';
  import { getMiseToolOptions, getAptPackageOptions } from '$lib/data/packages';
  import { shellOptions, dnsServices, acmeProviders, claudeThemes } from '$lib/data/options';
  import { validateSSHKey, extractSSHKeyName } from '$lib/utils/validation';
  import Card from '$components/ui/Card.svelte';
  import Button from '$components/ui/Button.svelte';
  import Input from '$components/ui/Input.svelte';

  interface Props {
    // Mode: 'global' for direct binding, 'profile' for override-based editing
    mode: 'global' | 'profile';
    // For 'profile' mode: functions to check/toggle overrides
    isOverridden?: (path: string) => boolean;
    toggleOverride?: (path: string) => void;
    // For getting and setting values
    getValue: <T>(path: string) => T;
    setValue: (path: string, value: unknown) => void;
    // Prefix for element IDs to avoid conflicts
    idPrefix?: string;
    // Optional toast function for notifications
    showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
  }

  let { mode, isOverridden, toggleOverride, getValue, setValue, idPrefix = '', showToast }: Props = $props();

  // Helper to show toast or console log
  function notify(message: string, type: 'success' | 'error' | 'info' = 'info') {
    if (showToast) {
      showToast(message, type);
    }
  }

  // SSH Key management
  let newSSHKeyName = $state('');
  let newSSHKeyPubKey = $state('');
  let sshKeyError = $state('');

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
      notify('Please enter a public key', 'error');
      return;
    }
    const validation = validateSSHKey(newSSHKeyPubKey);
    if (!validation.valid) {
      notify(validation.error ?? 'Invalid SSH key', 'error');
      return;
    }
    let name = newSSHKeyName.trim();
    if (!name) {
      name = extractSSHKeyName(newSSHKeyPubKey) ?? '';
    }
    if (!name) {
      const keys = getValue<Array<{name: string; pubKey: string}>>('ssh.keys');
      name = `key-${keys.length + 1}`;
    }
    const current = getValue<Array<{name: string; pubKey: string}>>('ssh.keys');
    setValue('ssh.keys', [...current, { name, pubKey: newSSHKeyPubKey.trim() }]);
    newSSHKeyName = '';
    newSSHKeyPubKey = '';
    sshKeyError = '';
    notify(`SSH key "${name}" added`, 'success');
  }

  function removeSSHKey(index: number) {
    const current = getValue<Array<{name: string; pubKey: string}>>('ssh.keys');
    setValue('ssh.keys', current.filter((_, i) => i !== index));
  }

  // Git credential management
  let newGitHost = $state('');
  let newGitUsername = $state('');
  let newGitToken = $state('');

  function addGitCredential() {
    if (!newGitHost.trim() || !newGitUsername.trim() || !newGitToken.trim()) {
      notify('Please fill in all fields', 'error');
      return;
    }
    const current = getValue<Array<{host: string; username: string; token: string}>>('git.credentials');
    setValue('git.credentials', [
      ...current,
      { host: newGitHost.trim(), username: newGitUsername.trim(), token: newGitToken.trim() },
    ]);
    newGitHost = '';
    newGitUsername = '';
    newGitToken = '';
  }

  function removeGitCredential(index: number) {
    const current = getValue<Array<{host: string; username: string; token: string}>>('git.credentials');
    setValue('git.credentials', current.filter((_, i) => i !== index));
  }

  // Environment variable management
  let newEnvVarName = $state('');
  let newEnvVarValue = $state('');
  let envVarNameError = $state('');

  // Validate env var name (POSIX compliant)
  const validEnvVarName = /^[A-Za-z_][A-Za-z0-9_]*$/;

  $effect(() => {
    if (newEnvVarName.trim()) {
      if (!validEnvVarName.test(newEnvVarName.trim())) {
        envVarNameError = 'Name must start with a letter or underscore, and contain only letters, digits, and underscores';
      } else {
        envVarNameError = '';
      }
    } else {
      envVarNameError = '';
    }
  });

  function addEnvVar() {
    if (!newEnvVarName.trim()) {
      notify('Please enter a variable name', 'error');
      return;
    }
    if (!validEnvVarName.test(newEnvVarName.trim())) {
      notify('Invalid environment variable name', 'error');
      return;
    }
    const current = getValue<Array<{name: string; value: string}>>('envVars') ?? [];
    // Check for duplicate names
    if (current.some(ev => ev.name === newEnvVarName.trim())) {
      notify('Environment variable already exists', 'error');
      return;
    }
    setValue('envVars', [...current, { name: newEnvVarName.trim(), value: newEnvVarValue }]);
    newEnvVarName = '';
    newEnvVarValue = '';
    envVarNameError = '';
    notify('Environment variable added', 'success');
  }

  function removeEnvVar(index: number) {
    const current = getValue<Array<{name: string; value: string}>>('envVars') ?? [];
    setValue('envVars', current.filter((_, i) => i !== index));
  }

  // Repository management
  let newRepo = $state('');

  function addRepo() {
    if (!newRepo.trim()) {
      notify('Please enter a repository URL', 'error');
      return;
    }
    const current = getValue<string[]>('repos');
    setValue('repos', [...current, newRepo.trim()]);
    newRepo = '';
  }

  function removeRepo(index: number) {
    const current = getValue<string[]>('repos');
    setValue('repos', current.filter((_, i) => i !== index));
  }

  // Package filtering
  let miseToolFilter = $state('');
  let aptPackageFilter = $state('');

  const miseOptions = getMiseToolOptions();
  const aptOptions = getAptPackageOptions();

  let filteredMiseOptions = $derived(
    miseToolFilter
      ? miseOptions.filter(
          (o) =>
            o.value.toLowerCase().includes(miseToolFilter.toLowerCase()) ||
            o.description.toLowerCase().includes(miseToolFilter.toLowerCase())
        )
      : miseOptions
  );

  let filteredAptOptions = $derived(
    aptPackageFilter
      ? aptOptions.filter(
          (o) =>
            o.value.toLowerCase().includes(aptPackageFilter.toLowerCase()) ||
            o.description.toLowerCase().includes(aptPackageFilter.toLowerCase())
        )
      : aptOptions
  );

  function toggleMiseTool(tool: string) {
    const current = getValue<string[]>('packages.mise');
    if (current.includes(tool)) {
      setValue(
        'packages.mise',
        current.filter((t) => t !== tool)
      );
    } else {
      setValue('packages.mise', [...current, tool]);
    }
  }

  function toggleAptPackage(pkg: string) {
    const current = getValue<string[]>('packages.apt');
    if (current.includes(pkg)) {
      setValue(
        'packages.apt',
        current.filter((p) => p !== pkg)
      );
    } else {
      setValue('packages.apt', [...current, pkg]);
    }
  }

  // Custom package inputs
  let customMiseTool = $state('');
  let customAptPackage = $state('');

  function addCustomMiseTool() {
    if (!customMiseTool.trim()) return;
    const current = getValue<string[]>('packages.mise');
    if (!current.includes(customMiseTool.trim())) {
      setValue('packages.mise', [...current, customMiseTool.trim()]);
    }
    customMiseTool = '';
  }

  function addCustomAptPackage() {
    if (!customAptPackage.trim()) return;
    const current = getValue<string[]>('packages.apt');
    if (!current.includes(customAptPackage.trim())) {
      setValue('packages.apt', [...current, customAptPackage.trim()]);
    }
    customAptPackage = '';
  }

  // Helper to check if field is disabled (profile mode only, when not overridden)
  function isDisabled(path: string): boolean {
    if (mode === 'global') return false;
    return isOverridden ? !isOverridden(path) : false;
  }

  // Helper to check if override is active
  function hasOverride(path: string): boolean {
    if (mode === 'global') return false;
    return isOverridden ? isOverridden(path) : false;
  }

  // Helper to toggle an override
  function toggle(path: string) {
    if (mode === 'profile' && toggleOverride) {
      toggleOverride(path);
    }
  }

  // Claude credentials.json upload
  let claudeCredentialsInputRef: HTMLInputElement | undefined = $state();

  function handleClaudeCredentialsUpload(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const credentials = JSON.parse(e.target?.result as string);
        setValue('claude.credentialsJson', credentials);
        notify('Claude credentials imported', 'success');
      } catch {
        notify('Invalid JSON file', 'error');
      }
    };
    reader.readAsText(file);
    input.value = ''; // Reset for re-upload
  }

  function clearClaudeCredentials() {
    setValue('claude.credentialsJson', null);
    notify('Claude credentials cleared', 'success');
  }

  // Helper to extract account info from credentials
  function getClaudeAccountInfo(
    credentials: Record<string, unknown> | null
  ): { email?: string; org?: string; expires?: string; isExpired?: boolean } | null {
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
</script>

<!-- Git Settings -->
<Card title="Git Settings">
  <div class="space-y-4">
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('git.userName')}
          onchange={() => toggle('git.userName')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}git-username" class="block text-sm font-medium mb-1.5">User Name</label>
        <input
          id="{idPrefix}git-username"
          type="text"
          value={getValue('git.userName')}
          onchange={(e) => setValue('git.userName', e.currentTarget.value)}
          disabled={isDisabled('git.userName')}
          placeholder="John Doe"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
    </div>

    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('git.userEmail')}
          onchange={() => toggle('git.userEmail')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}git-email" class="block text-sm font-medium mb-1.5">Email</label>
        <input
          id="{idPrefix}git-email"
          type="email"
          value={getValue('git.userEmail')}
          onchange={(e) => setValue('git.userEmail', e.currentTarget.value)}
          disabled={isDisabled('git.userEmail')}
          placeholder="john@example.com"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
    </div>
  </div>
</Card>

<!-- SSH Keys -->
<Card title="SSH Keys">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('ssh.keys')}
        onchange={() => toggle('ssh.keys')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override SSH keys for this profile</p>
    </div>
  {/if}

  {#if mode === 'global' || hasOverride('ssh.keys')}
    {#if getValue<Array<{name: string; pubKey: string}>>('ssh.keys').length > 0}
      <div class="space-y-2 mb-4">
        {#each getValue<Array<{name: string; pubKey: string}>>('ssh.keys') as key, i}
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
      <div>
        <label for="{idPrefix}ssh-name" class="block text-sm font-medium mb-1.5">Name (optional)</label>
        <input
          id="{idPrefix}ssh-name"
          type="text"
          bind:value={newSSHKeyName}
          placeholder="my-key"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        />
        <p class="text-xs text-muted-foreground mt-1">Auto-extracted from key comment if empty</p>
      </div>
      <div>
        <label for="{idPrefix}ssh-pubkey" class="block text-sm font-medium mb-1.5">Public Key</label>
        <textarea
          id="{idPrefix}ssh-pubkey"
          bind:value={newSSHKeyPubKey}
          class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 placeholder:text-placeholder resize-y font-mono text-sm
                 {sshKeyError ? 'border-destructive' : 'border-border'}"
          placeholder="ssh-ed25519 AAAA..."
        ></textarea>
        {#if sshKeyError}
          <p class="text-sm text-destructive mt-1">{sshKeyError}</p>
        {/if}
      </div>
      <Button variant="secondary" onclick={addSSHKey}>Add SSH Key</Button>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground">Using global SSH keys configuration.</p>
  {/if}
</Card>

<!-- Git Credentials -->
<Card title="Git Credentials">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('git.credentials')}
        onchange={() => toggle('git.credentials')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override Git credentials for this profile</p>
    </div>
  {/if}

  {#if mode === 'global' || hasOverride('git.credentials')}
    {#if getValue<Array<{host: string; username: string; token: string}>>('git.credentials').length > 0}
      <div class="space-y-2 mb-4">
        {#each getValue<Array<{host: string; username: string; token: string}>>('git.credentials') as cred, i}
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
      <div>
        <label for="{idPrefix}git-host" class="block text-sm font-medium mb-1.5">Host</label>
        <input
          id="{idPrefix}git-host"
          type="text"
          bind:value={newGitHost}
          placeholder="github.com"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        />
      </div>
      <div>
        <label for="{idPrefix}git-username" class="block text-sm font-medium mb-1.5">Username</label>
        <input
          id="{idPrefix}git-username"
          type="text"
          bind:value={newGitUsername}
          placeholder="username"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        />
      </div>
      <div>
        <label for="{idPrefix}git-token" class="block text-sm font-medium mb-1.5">Token</label>
        <input
          id="{idPrefix}git-token"
          type="password"
          bind:value={newGitToken}
          placeholder="ghp_..."
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        />
      </div>
      <Button variant="secondary" onclick={addGitCredential}>Add Credential</Button>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground">Using global Git credentials configuration.</p>
  {/if}
</Card>

<!-- Repositories -->
<Card title="Repositories">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('repos')}
        onchange={() => toggle('repos')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override repositories for this profile</p>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground mb-4">Repositories to automatically clone when creating a new devbox.</p>
  {/if}

  {#if mode === 'global' || hasOverride('repos')}
    {#if getValue<string[]>('repos').length > 0}
      <div class="space-y-2 mb-4">
        {#each getValue<string[]>('repos') as repo, i}
          <div class="flex items-center justify-between p-3 bg-muted rounded-md">
            <p class="text-sm font-mono truncate flex-1">{repo}</p>
            <Button variant="ghost" size="sm" onclick={() => removeRepo(i)}>Remove</Button>
          </div>
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
  {:else}
    <p class="text-sm text-muted-foreground">Using global repositories configuration.</p>
  {/if}
</Card>

<!-- Environment Variables -->
<Card title="Environment Variables">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('envVars')}
        onchange={() => toggle('envVars')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override environment variables for this profile</p>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground mb-4">Custom environment variables to inject into the server environment.</p>
  {/if}

  {#if mode === 'global' || hasOverride('envVars')}
    {@const envVars = getValue<Array<{name: string; value: string}>>('envVars') ?? []}
    {#if envVars.length > 0}
      <div class="space-y-2 mb-4">
        {#each envVars as envVar, i}
          <div class="flex items-center justify-between p-3 bg-muted rounded-md">
            <div>
              <p class="font-medium font-mono">{envVar.name}</p>
              <p class="text-sm text-muted-foreground">••••••••</p>
            </div>
            <Button variant="ghost" size="sm" onclick={() => removeEnvVar(i)}>Remove</Button>
          </div>
        {/each}
      </div>
    {/if}

    <div class="space-y-3 p-4 border border-border rounded-md">
      <div>
        <label for="{idPrefix}env-name" class="block text-sm font-medium mb-1.5">Name</label>
        <input
          id="{idPrefix}env-name"
          type="text"
          bind:value={newEnvVarName}
          placeholder="DATABASE_URL"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 rounded-md font-mono
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 {envVarNameError ? 'border-destructive' : 'border-border'}"
        />
        {#if envVarNameError}
          <p class="text-sm text-destructive mt-1">{envVarNameError}</p>
        {/if}
      </div>
      <div>
        <label for="{idPrefix}env-value" class="block text-sm font-medium mb-1.5">Value</label>
        <input
          id="{idPrefix}env-value"
          type="password"
          bind:value={newEnvVarValue}
          placeholder="postgres://localhost:5432/db"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
        />
      </div>
      <Button variant="secondary" onclick={addEnvVar}>Add Variable</Button>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground">Using global environment variables configuration.</p>
  {/if}
</Card>

<!-- Hetzner Settings -->
<Card title="Hetzner Settings">
  <div class="space-y-4">
    <!-- Server Type -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('hetzner.serverType')}
          onchange={() => toggle('hetzner.serverType')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}server-type" class="block text-sm font-medium mb-1.5">Server Type</label>
        <select
          id="{idPrefix}server-type"
          value={getValue('hetzner.serverType')}
          onchange={(e) => setValue('hetzner.serverType', e.currentTarget.value)}
          disabled={isDisabled('hetzner.serverType')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#if serversStore.serverTypes.length === 0}
            <option value={getValue('hetzner.serverType')}>{getValue('hetzner.serverType')}</option>
          {:else}
            {#each serversStore.serverTypes as type}
              <option value={type.name}>{type.name} - {type.cores} vCPU, {type.memory}GB RAM</option>
            {/each}
          {/if}
        </select>
      </div>
    </div>

    <!-- Location -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('hetzner.location')}
          onchange={() => toggle('hetzner.location')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}location" class="block text-sm font-medium mb-1.5">Location</label>
        <select
          id="{idPrefix}location"
          value={getValue('hetzner.location')}
          onchange={(e) => setValue('hetzner.location', e.currentTarget.value)}
          disabled={isDisabled('hetzner.location')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#if serversStore.locations.length === 0}
            <option value={getValue('hetzner.location')}>{getValue('hetzner.location')}</option>
          {:else}
            {#each serversStore.locations as loc}
              <option value={loc.name}>{loc.name} - {loc.city}, {loc.country}</option>
            {/each}
          {/if}
        </select>
      </div>
    </div>

    <!-- Base Image -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('hetzner.baseImage')}
          onchange={() => toggle('hetzner.baseImage')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}base-image" class="block text-sm font-medium mb-1.5">Base Image</label>
        <select
          id="{idPrefix}base-image"
          value={getValue('hetzner.baseImage')}
          onchange={(e) => setValue('hetzner.baseImage', e.currentTarget.value)}
          disabled={isDisabled('hetzner.baseImage')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#if serversStore.images.length === 0}
            <option value={getValue('hetzner.baseImage')}>{getValue('hetzner.baseImage')}</option>
          {:else}
            {#each serversStore.images as img}
              <option value={img.name}>{img.description}</option>
            {/each}
          {/if}
        </select>
      </div>
    </div>
  </div>
</Card>

<!-- Shell -->
<Card title="Shell">
  <div class="space-y-4">
    <!-- Default Shell -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('shell.default')}
          onchange={() => toggle('shell.default')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}default-shell" class="block text-sm font-medium mb-1.5">Default Shell</label>
        <select
          id="{idPrefix}default-shell"
          value={getValue('shell.default')}
          onchange={(e) => setValue('shell.default', e.currentTarget.value)}
          disabled={isDisabled('shell.default')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#each shellOptions as shell}
            <option value={shell.value}>{shell.label} - {shell.description}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- Starship -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('shell.starship')}
          onchange={() => toggle('shell.starship')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('shell.starship')}
          onchange={(e) => setValue('shell.starship', e.currentTarget.checked)}
          disabled={isDisabled('shell.starship')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('shell.starship') ? 'opacity-50' : ''}>Enable Starship prompt</span>
      </label>
    </div>
  </div>
</Card>

<!-- Services -->
<Card title="Services">
  <div class="space-y-4">
    <!-- VS Code Server -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.codeServer')}
          onchange={() => toggle('services.codeServer')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('services.codeServer')}
          onchange={(e) => setValue('services.codeServer', e.currentTarget.checked)}
          disabled={isDisabled('services.codeServer')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('services.codeServer') ? 'opacity-50' : ''}>VS Code Server</span>
      </label>
    </div>

    <!-- Claude Terminal -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.claudeTerminal')}
          onchange={() => toggle('services.claudeTerminal')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('services.claudeTerminal')}
          onchange={(e) => setValue('services.claudeTerminal', e.currentTarget.checked)}
          disabled={isDisabled('services.claudeTerminal')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('services.claudeTerminal') ? 'opacity-50' : ''}>Claude Terminal</span>
      </label>
    </div>

    <!-- Shell Terminal -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.shellTerminal')}
          onchange={() => toggle('services.shellTerminal')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('services.shellTerminal')}
          onchange={(e) => setValue('services.shellTerminal', e.currentTarget.checked)}
          disabled={isDisabled('services.shellTerminal')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('services.shellTerminal') ? 'opacity-50' : ''}>Shell Terminal</span>
      </label>
    </div>

    <!-- DNS Service -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.dnsService')}
          onchange={() => toggle('services.dnsService')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}dns-service" class="block text-sm font-medium mb-1.5">DNS Service</label>
        <select
          id="{idPrefix}dns-service"
          value={getValue('services.dnsService')}
          onchange={(e) => setValue('services.dnsService', e.currentTarget.value)}
          disabled={isDisabled('services.dnsService')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#each dnsServices as dns}
            <option value={dns.value}>{dns.label} - {dns.description}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- ACME Provider -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.acmeProvider')}
          onchange={() => toggle('services.acmeProvider')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}acme-provider" class="block text-sm font-medium mb-1.5">ACME Provider</label>
        <select
          id="{idPrefix}acme-provider"
          value={getValue('services.acmeProvider')}
          onchange={(e) => setValue('services.acmeProvider', e.currentTarget.value)}
          disabled={isDisabled('services.acmeProvider')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#each acmeProviders as provider}
            <option value={provider.value}>{provider.label} - {provider.description}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- ACME Email -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('services.acmeEmail')}
          onchange={() => toggle('services.acmeEmail')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}acme-email" class="block text-sm font-medium mb-1.5">ACME Email (optional)</label>
        <input
          id="{idPrefix}acme-email"
          type="email"
          value={getValue('services.acmeEmail')}
          onchange={(e) => setValue('services.acmeEmail', e.currentTarget.value)}
          disabled={isDisabled('services.acmeEmail')}
          placeholder="admin@example.com"
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <p class="text-xs text-muted-foreground mt-1">For Let's Encrypt certificates</p>
      </div>
    </div>

    <!-- ZeroSSL EAB Credentials -->
    {#if getValue('services.acmeProvider') === 'zerossl'}
      <div class="bg-muted/30 rounded-md p-4 space-y-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.zerosslEabKeyId')}
              onchange={() => toggle('services.zerosslEabKeyId')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}zerossl-key-id" class="block text-sm font-medium mb-1.5">ZeroSSL EAB Key ID</label>
            <input
              id="{idPrefix}zerossl-key-id"
              type="text"
              value={getValue('services.zerosslEabKeyId')}
              onchange={(e) => setValue('services.zerosslEabKeyId', e.currentTarget.value)}
              disabled={isDisabled('services.zerosslEabKeyId')}
              placeholder="From zerossl.com/acme"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.zerosslEabKey')}
              onchange={() => toggle('services.zerosslEabKey')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}zerossl-hmac" class="block text-sm font-medium mb-1.5">ZeroSSL EAB HMAC Key</label>
            <input
              id="{idPrefix}zerossl-hmac"
              type="password"
              value={getValue('services.zerosslEabKey')}
              onchange={(e) => setValue('services.zerosslEabKey', e.currentTarget.value)}
              disabled={isDisabled('services.zerosslEabKey')}
              placeholder="From zerossl.com/acme"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
      </div>
    {/if}

    <!-- Actalis EAB Credentials -->
    {#if getValue('services.acmeProvider') === 'actalis'}
      <div class="bg-muted/30 rounded-md p-4 space-y-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.actalisEabKeyId')}
              onchange={() => toggle('services.actalisEabKeyId')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}actalis-key-id" class="block text-sm font-medium mb-1.5">Actalis EAB Key ID</label>
            <input
              id="{idPrefix}actalis-key-id"
              type="text"
              value={getValue('services.actalisEabKeyId')}
              onchange={(e) => setValue('services.actalisEabKeyId', e.currentTarget.value)}
              disabled={isDisabled('services.actalisEabKeyId')}
              placeholder="From Actalis ACME dashboard"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.actalisEabKey')}
              onchange={() => toggle('services.actalisEabKey')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}actalis-hmac" class="block text-sm font-medium mb-1.5">Actalis EAB HMAC Key</label>
            <input
              id="{idPrefix}actalis-hmac"
              type="password"
              value={getValue('services.actalisEabKey')}
              onchange={(e) => setValue('services.actalisEabKey', e.currentTarget.value)}
              disabled={isDisabled('services.actalisEabKey')}
              placeholder="From Actalis ACME dashboard"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
      </div>
    {/if}

    <!-- Custom ACME Credentials -->
    {#if getValue('services.acmeProvider') === 'custom'}
      <div class="bg-muted/30 rounded-md p-4 space-y-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customAcmeUrl')}
              onchange={() => toggle('services.customAcmeUrl')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-acme-url" class="block text-sm font-medium mb-1.5">Custom ACME Directory URL</label>
            <input
              id="{idPrefix}custom-acme-url"
              type="url"
              value={getValue('services.customAcmeUrl')}
              onchange={(e) => setValue('services.customAcmeUrl', e.currentTarget.value)}
              disabled={isDisabled('services.customAcmeUrl')}
              placeholder="https://acme.example.com/directory"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customEabKeyId')}
              onchange={() => toggle('services.customEabKeyId')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-key-id" class="block text-sm font-medium mb-1.5">EAB Key ID (optional)</label>
            <input
              id="{idPrefix}custom-key-id"
              type="text"
              value={getValue('services.customEabKeyId')}
              onchange={(e) => setValue('services.customEabKeyId', e.currentTarget.value)}
              disabled={isDisabled('services.customEabKeyId')}
              placeholder="Leave empty if not required"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customEabKey')}
              onchange={() => toggle('services.customEabKey')}
              class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-hmac" class="block text-sm font-medium mb-1.5">EAB HMAC Key (optional)</label>
            <input
              id="{idPrefix}custom-hmac"
              type="password"
              value={getValue('services.customEabKey')}
              onchange={(e) => setValue('services.customEabKey', e.currentTarget.value)}
              disabled={isDisabled('services.customEabKey')}
              placeholder="Leave empty if not required"
              class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                     focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>
        </div>
      </div>
    {/if}
  </div>
</Card>

<!-- Auto-Delete -->
<Card title="Auto-Delete">
  <div class="space-y-4">
    <!-- Enabled -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('autoDelete.enabled')}
          onchange={() => toggle('autoDelete.enabled')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('autoDelete.enabled')}
          onchange={(e) => setValue('autoDelete.enabled', e.currentTarget.checked)}
          disabled={isDisabled('autoDelete.enabled')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('autoDelete.enabled') ? 'opacity-50' : ''}>Enable auto-delete for idle servers</span>
      </label>
    </div>

    <!-- Timeout -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('autoDelete.timeoutMinutes')}
          onchange={() => toggle('autoDelete.timeoutMinutes')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}timeout" class="block text-sm font-medium mb-1.5">Timeout (minutes)</label>
        <input
          id="{idPrefix}timeout"
          type="number"
          value={getValue('autoDelete.timeoutMinutes')}
          onchange={(e) => setValue('autoDelete.timeoutMinutes', parseInt(e.currentTarget.value) || 0)}
          disabled={isDisabled('autoDelete.timeoutMinutes')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
    </div>

    <!-- Warning Minutes -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('autoDelete.warningMinutes')}
          onchange={() => toggle('autoDelete.warningMinutes')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}warning" class="block text-sm font-medium mb-1.5">Warning (minutes before)</label>
        <input
          id="{idPrefix}warning"
          type="number"
          value={getValue('autoDelete.warningMinutes')}
          onchange={(e) => setValue('autoDelete.warningMinutes', parseInt(e.currentTarget.value) || 0)}
          disabled={isDisabled('autoDelete.warningMinutes')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
    </div>
  </div>
</Card>

<!-- Packages - Mise Tools -->
<Card title="Packages - Mise Tools">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('packages.mise')}
        onchange={() => toggle('packages.mise')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override mise tools for this profile</p>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground mb-4">Select runtime tools to install via mise.</p>
  {/if}

  {#if mode === 'global' || hasOverride('packages.mise')}
    {#if getValue<string[]>('packages.mise').length > 0}
      <div class="flex flex-wrap gap-2 mb-4">
        {#each getValue<string[]>('packages.mise') as tool}
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
            checked={getValue<string[]>('packages.mise').includes(option.value)}
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
  {:else}
    <p class="text-sm text-muted-foreground">Using global mise tools configuration.</p>
  {/if}
</Card>

<!-- Packages - APT -->
<Card title="Packages - APT">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('packages.apt')}
        onchange={() => toggle('packages.apt')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override APT packages for this profile</p>
    </div>
  {:else}
    <p class="text-sm text-muted-foreground mb-4">Select system packages to install via apt.</p>
  {/if}

  {#if mode === 'global' || hasOverride('packages.apt')}
    {#if getValue<string[]>('packages.apt').length > 0}
      <div class="flex flex-wrap gap-2 mb-4">
        {#each getValue<string[]>('packages.apt') as pkg}
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
            checked={getValue<string[]>('packages.apt').includes(option.value)}
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
  {:else}
    <p class="text-sm text-muted-foreground">Using global APT packages configuration.</p>
  {/if}
</Card>

<!-- Claude Code -->
<Card title="Claude Code">
  <div class="space-y-4">
    <!-- Credentials File Upload -->
    {#if mode === 'profile'}
      <div class="flex items-start gap-3 mb-4">
        <input
          type="checkbox"
          checked={hasOverride('claude.credentialsJson')}
          onchange={() => toggle('claude.credentialsJson')}
          class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
        <p class="text-sm text-muted-foreground">Override credentials file for this profile</p>
      </div>
    {/if}

    {#if mode === 'global' || hasOverride('claude.credentialsJson')}
      {@const credentials = getValue<Record<string, unknown> | null>('claude.credentialsJson')}
      {@const accountInfo = getClaudeAccountInfo(credentials)}
      <div class="space-y-3 {mode === 'profile' ? 'ml-8' : ''}">
        <p class="text-sm font-medium">Credentials File</p>
        <div class="flex items-center gap-2">
          <Button variant="secondary" onclick={() => claudeCredentialsInputRef?.click()}>
            Upload credentials.json
          </Button>
          {#if credentials}
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
        {#if credentials}
          <div class="bg-muted/30 rounded-md p-3">
            <div class="text-sm flex items-center gap-2">
              <span class="text-success">✓</span>
              <span>Credentials loaded</span>
            </div>
            {#if accountInfo}
              <div class="text-sm text-muted-foreground mt-1 space-y-0.5">
                {#if accountInfo.email}
                  <div><span class="text-muted-foreground">Account:</span> {accountInfo.email}</div>
                {/if}
                {#if accountInfo.org}
                  <div><span class="text-muted-foreground">Org:</span> {accountInfo.org}</div>
                {/if}
                {#if accountInfo.expires}
                  <div>
                    <span class="text-muted-foreground">Expires:</span>
                    <span class={accountInfo.isExpired ? 'text-destructive' : ''}>{accountInfo.expires}</span>
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/if}
        <p class="text-xs text-muted-foreground">Upload your ~/.claude/credentials.json file for OAuth authentication</p>
      </div>
    {:else}
      <p class="text-sm text-muted-foreground ml-8">Using global credentials file.</p>
    {/if}

    <!-- API Key -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('claude.apiKey')}
          onchange={() => toggle('claude.apiKey')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}claude-apikey" class="block text-sm font-medium mb-1.5">API Key</label>
        <input
          id="{idPrefix}claude-apikey"
          type="password"
          value={getValue('claude.apiKey')}
          onchange={(e) => setValue('claude.apiKey', e.currentTarget.value)}
          disabled={isDisabled('claude.apiKey')}
          placeholder="sk-ant-..."
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <p class="text-xs text-muted-foreground mt-1">Your Anthropic API key</p>
      </div>
    </div>

    <!-- Theme -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('claude.theme')}
          onchange={() => toggle('claude.theme')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}claude-theme" class="block text-sm font-medium mb-1.5">Theme</label>
        <select
          id="{idPrefix}claude-theme"
          value={getValue('claude.theme')}
          onchange={(e) => setValue('claude.theme', e.currentTarget.value)}
          disabled={isDisabled('claude.theme')}
          class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {#each claudeThemes as theme}
            <option value={theme.value}>{theme.label} - {theme.description}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- Skip Permissions -->
    <div class="flex items-center gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('claude.skipPermissions')}
          onchange={() => toggle('claude.skipPermissions')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <label class="flex items-center gap-3 cursor-pointer flex-1">
        <input
          type="checkbox"
          checked={getValue('claude.skipPermissions')}
          onchange={(e) => setValue('claude.skipPermissions', e.currentTarget.checked)}
          disabled={isDisabled('claude.skipPermissions')}
          class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                 disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <span class={isDisabled('claude.skipPermissions') ? 'opacity-50' : ''}>Enable --dangerously-skip-permissions flag</span>
      </label>
    </div>

    <!-- Settings JSON -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('claude.settings')}
          onchange={() => toggle('claude.settings')}
          class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}claude-settings" class="block text-sm font-medium mb-1.5">Settings JSON</label>
        <textarea
          id="{idPrefix}claude-settings"
          value={getValue('claude.settings')}
          onchange={(e) => setValue('claude.settings', e.currentTarget.value)}
          disabled={isDisabled('claude.settings')}
          class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                 focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                 placeholder:text-placeholder resize-y font-mono text-sm
                 disabled:opacity-50 disabled:cursor-not-allowed"
          placeholder={'{"theme": "dark"}'}
        ></textarea>
      </div>
    </div>
  </div>
</Card>
