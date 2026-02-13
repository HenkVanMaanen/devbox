<script lang="ts">
  import { serversStore } from '$lib/stores/servers.svelte';
  import { dnsServices, acmeProviders } from '$lib/data/options';
  import { validateSSHKey, extractSSHKeyName } from '$lib/utils/validation';
  import Card from '$components/ui/Card.svelte';
  import Button from '$components/ui/Button.svelte';

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
</script>

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

<!-- Chezmoi Dotfiles -->
<Card title="Chezmoi Dotfiles">
  {#if mode === 'profile'}
    <div class="flex items-start gap-3 mb-4">
      <input
        type="checkbox"
        checked={hasOverride('chezmoi.repoUrl')}
        onchange={() => toggle('chezmoi.repoUrl')}
        class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
      />
      <p class="text-sm text-muted-foreground">Override chezmoi dotfiles for this profile</p>
    </div>
  {/if}

  <div class="space-y-4">
    <div>
      <label for="{idPrefix}chezmoi-repo" class="block text-sm font-medium mb-1.5">Dotfiles Repository URL</label>
      <input
        id="{idPrefix}chezmoi-repo"
        type="text"
        value={getValue('chezmoi.repoUrl')}
        onchange={(e) => setValue('chezmoi.repoUrl', e.currentTarget.value.trim())}
        disabled={isDisabled('chezmoi.repoUrl')}
        placeholder="https://github.com/user/dotfiles.git"
        class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
               focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
               disabled:opacity-50 disabled:cursor-not-allowed"
      />
      <p class="text-xs text-muted-foreground mt-1">Private dotfiles repo managed by <a href="https://github.com/twpayne/chezmoi" target="_blank" class="text-primary hover:underline">chezmoi</a>. Runs on the server to set up your shell, packages, git config, and environment.</p>
    </div>

    <div>
      <label for="{idPrefix}chezmoi-age-key" class="block text-sm font-medium mb-1.5">Age Key (optional)</label>
      <textarea
        id="{idPrefix}chezmoi-age-key"
        value={getValue('chezmoi.ageKey')}
        onchange={(e) => setValue('chezmoi.ageKey', e.currentTarget.value)}
        disabled={isDisabled('chezmoi.repoUrl')}
        placeholder="# created: 2024-01-01T00:00:00Z&#10;# public key: age1...&#10;AGE-SECRET-KEY-1..."
        class="w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
               focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
               disabled:opacity-50 disabled:cursor-not-allowed
               placeholder:text-placeholder resize-y font-mono text-sm"
      ></textarea>
      <p class="text-xs text-muted-foreground mt-1">Private key for decrypting chezmoi secrets. Written to <code class="text-xs bg-muted px-1 py-0.5 rounded">~/.config/chezmoi/key.txt</code></p>
    </div>

    <div class="border-t border-border pt-4">
      {#if mode === 'profile'}
        <div class="flex items-start gap-3 mb-4">
          <input
            type="checkbox"
            checked={hasOverride('git.credential')}
            onchange={() => toggle('git.credential')}
            class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <p class="text-sm text-muted-foreground">Override git credential for this profile</p>
        </div>
      {/if}

      <p class="text-sm font-medium mb-3">Git Credential</p>
      <p class="text-xs text-muted-foreground mb-3">Used to clone your chezmoi repo and project repositories. Chezmoi manages additional credentials.</p>
      <div class="space-y-3">
        <div>
          <label for="{idPrefix}git-host" class="block text-sm font-medium mb-1.5">Host</label>
          <input
            id="{idPrefix}git-host"
            type="text"
            value={getValue('git.credential.host')}
            onchange={(e) => setValue('git.credential.host', e.currentTarget.value.trim())}
            disabled={isDisabled('git.credential')}
            placeholder="github.com"
            class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                   focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                   disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>
        <div>
          <label for="{idPrefix}git-username" class="block text-sm font-medium mb-1.5">Username</label>
          <input
            id="{idPrefix}git-username"
            type="text"
            value={getValue('git.credential.username')}
            onchange={(e) => setValue('git.credential.username', e.currentTarget.value.trim())}
            disabled={isDisabled('git.credential')}
            placeholder="username"
            class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                   focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                   disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>
        <div>
          <label for="{idPrefix}git-token" class="block text-sm font-medium mb-1.5">Token</label>
          <input
            id="{idPrefix}git-token"
            type="password"
            value={getValue('git.credential.token')}
            onchange={(e) => setValue('git.credential.token', e.currentTarget.value.trim())}
            disabled={isDisabled('git.credential')}
            placeholder="ghp_..."
            class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                   focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                   disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>
      </div>
    </div>
  </div>
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

<!-- Services -->
<Card title="Services">
  <div class="space-y-4">
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

    <!-- Custom DNS Domain (shown when dnsService is 'custom') -->
    {#if getValue('services.dnsService') === 'custom'}
      <div class="flex items-start gap-3">
        {#if mode === 'profile'}
          <input
            type="checkbox"
            checked={hasOverride('services.customDnsDomain')}
            onchange={() => toggle('services.customDnsDomain')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
        {/if}
        <div class="flex-1">
          <label for="{idPrefix}custom-dns-domain" class="block text-sm font-medium mb-1.5">Custom Domain</label>
          <input
            id="{idPrefix}custom-dns-domain"
            type="text"
            value={getValue('services.customDnsDomain')}
            onchange={(e) => setValue('services.customDnsDomain', e.currentTarget.value.trim().toLowerCase())}
            disabled={isDisabled('services.customDnsDomain')}
            placeholder="dev.example.com"
            required
            pattern="[a-z0-9][a-z0-9\.\-]*[a-z0-9]\.[a-z]&#123;2,&#125;"
            class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
                   focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
                   disabled:opacity-50 disabled:cursor-not-allowed"
          />
          <p class="text-sm text-muted-foreground mt-1.5">
            Delegate this domain to sslip.io nameservers:
            <code class="text-xs bg-muted px-1 py-0.5 rounded">ns-aws.sslip.io</code>,
            <code class="text-xs bg-muted px-1 py-0.5 rounded">ns-azure.sslip.io</code>,
            <code class="text-xs bg-muted px-1 py-0.5 rounded">ns-gce.sslip.io</code>
          </p>
        </div>
      </div>
    {/if}

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
