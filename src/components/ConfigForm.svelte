<script lang="ts">
  import CustomCloudInitEditor from '$components/CustomCloudInitEditor.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import { acmeProviders, dnsServices } from '$lib/data/options';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { extractSSHKeyName, validateSSHKey } from '$lib/utils/validation';

  interface Props {
    // For getting and setting values
    getValue: (path: string) => unknown;
    // Prefix for element IDs to avoid conflicts
    idPrefix?: string;
    // For 'profile' mode: functions to check/toggle overrides
    isOverridden?: (path: string) => boolean;
    // Mode: 'global' for direct binding, 'profile' for override-based editing
    mode: 'global' | 'profile';
    setValue: (path: string, value: unknown) => void;
    // Optional toast function for notifications
    showToast?: (message: string, type: 'error' | 'info' | 'success') => void;
    toggleOverride?: (path: string) => void;
  }

  let { getValue, idPrefix = '', isOverridden, mode, setValue, showToast, toggleOverride }: Props = $props();

  // Helper to show toast or console log
  function notify(message: string, type: 'error' | 'info' | 'success' = 'info') {
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
      const keys = getValue('ssh.keys') as { name: string; pubKey: string }[];
      name = `key-${keys.length + 1}`;
    }
    const current = getValue('ssh.keys') as { name: string; pubKey: string }[];
    setValue('ssh.keys', [...current, { name, pubKey: newSSHKeyPubKey.trim() }]);
    newSSHKeyName = '';
    newSSHKeyPubKey = '';
    sshKeyError = '';
    notify(`SSH key "${name}" added`, 'success');
  }

  function removeSSHKey(index: number) {
    const current = getValue('ssh.keys') as { name: string; pubKey: string }[];
    setValue(
      'ssh.keys',
      current.filter((_, i) => i !== index),
    );
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
    <div class="mb-4 flex items-start gap-3">
      <input
        type="checkbox"
        checked={hasOverride('ssh.keys')}
        onchange={() => {
          toggle('ssh.keys');
        }}
        class="border-border text-primary focus:ring-focus bg-background mt-1 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
      />
      <p class="text-muted-foreground text-sm">Override SSH keys for this profile</p>
    </div>
  {/if}

  {#if mode === 'global' || hasOverride('ssh.keys')}
    {#if (getValue('ssh.keys') as { name: string; pubKey: string }[]).length > 0}
      <div class="mb-4 space-y-2">
        {#each getValue('ssh.keys') as { name: string; pubKey: string }[] as key, i (i)}
          <div class="bg-muted flex items-center justify-between rounded-md p-3">
            <div>
              <p class="font-medium">{key.name}</p>
              <p class="text-muted-foreground max-w-md truncate font-mono text-sm">{key.pubKey.slice(0, 50)}...</p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onclick={() => {
                removeSSHKey(i);
              }}>Remove</Button
            >
          </div>
        {/each}
      </div>
    {/if}

    <div class="border-border space-y-3 rounded-md border p-4">
      <div>
        <label for="{idPrefix}ssh-name" class="mb-1.5 block text-sm font-medium">Name (optional)</label>
        <input
          id="{idPrefix}ssh-name"
          type="text"
          bind:value={newSSHKeyName}
          placeholder="my-key"
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none"
        />
        <p class="text-muted-foreground mt-1 text-xs">Auto-extracted from key comment if empty</p>
      </div>
      <div>
        <label for="{idPrefix}ssh-pubkey" class="mb-1.5 block text-sm font-medium">Public Key</label>
        <textarea
          id="{idPrefix}ssh-pubkey"
          bind:value={newSSHKeyPubKey}
          class="bg-background focus:ring-focus focus:border-primary placeholder:text-placeholder min-h-[88px] w-full resize-y rounded-md
                 border-2 px-3 py-2 font-mono
                 text-base text-sm focus:ring-3 focus:outline-none
                 {sshKeyError ? 'border-destructive' : 'border-border'}"
          placeholder="ssh-ed25519 AAAA..."
        ></textarea>
        {#if sshKeyError}
          <p class="text-destructive mt-1 text-sm">{sshKeyError}</p>
        {/if}
      </div>
      <Button variant="secondary" onclick={addSSHKey}>Add SSH Key</Button>
    </div>
  {:else}
    <p class="text-muted-foreground text-sm">Using global SSH keys configuration.</p>
  {/if}
</Card>

<!-- Chezmoi Dotfiles -->
<Card title="Chezmoi Dotfiles">
  {#if mode === 'profile'}
    <div class="mb-4 flex items-start gap-3">
      <input
        type="checkbox"
        checked={hasOverride('chezmoi.repoUrl')}
        onchange={() => {
          toggle('chezmoi.repoUrl');
        }}
        class="border-border text-primary focus:ring-focus bg-background mt-1 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
      />
      <p class="text-muted-foreground text-sm">Override chezmoi dotfiles for this profile</p>
    </div>
  {/if}

  <div class="space-y-4">
    <div>
      <label for="{idPrefix}chezmoi-repo" class="mb-1.5 block text-sm font-medium">Dotfiles Repository URL</label>
      <input
        id="{idPrefix}chezmoi-repo"
        type="text"
        value={getValue('chezmoi.repoUrl')}
        onchange={(e) => {
          setValue('chezmoi.repoUrl', e.currentTarget.value.trim());
        }}
        disabled={isDisabled('chezmoi.repoUrl')}
        placeholder="https://github.com/user/dotfiles.git"
        class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
               py-2 text-base focus:ring-3 focus:outline-none
               disabled:cursor-not-allowed disabled:opacity-50"
      />
      <p class="text-muted-foreground mt-1 text-xs">
        Private dotfiles repo managed by <a
          href="https://github.com/twpayne/chezmoi"
          target="_blank"
          class="text-primary hover:underline">chezmoi</a
        >. Runs on the server to set up your shell, packages, git config, and environment.
      </p>
    </div>

    <div>
      <label for="{idPrefix}chezmoi-age-key" class="mb-1.5 block text-sm font-medium">Age Key (optional)</label>
      <textarea
        id="{idPrefix}chezmoi-age-key"
        value={getValue('chezmoi.ageKey') as string}
        onchange={(e) => {
          setValue('chezmoi.ageKey', e.currentTarget.value);
        }}
        disabled={isDisabled('chezmoi.repoUrl')}
        placeholder="# created: 2024-01-01T00:00:00Z&#10;# public key: age1...&#10;AGE-SECRET-KEY-1..."
        class="bg-background border-border focus:ring-focus focus:border-primary placeholder:text-placeholder min-h-[88px] w-full resize-y rounded-md
               border-2 px-3 py-2 font-mono
               text-base text-sm
               focus:ring-3 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
      ></textarea>
      <p class="text-muted-foreground mt-1 text-xs">
        Private key for decrypting chezmoi secrets. Written to <code class="bg-muted rounded px-1 py-0.5 text-xs"
          >~/.config/chezmoi/key.txt</code
        >
      </p>
    </div>

    <div class="border-border border-t pt-4">
      {#if mode === 'profile'}
        <div class="mb-4 flex items-start gap-3">
          <input
            type="checkbox"
            checked={hasOverride('git.credential')}
            onchange={() => {
              toggle('git.credential');
            }}
            class="border-border text-primary focus:ring-focus bg-background mt-1 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
          />
          <p class="text-muted-foreground text-sm">Override git credential for this profile</p>
        </div>
      {/if}

      <p class="mb-3 text-sm font-medium">Git Credential</p>
      <p class="text-muted-foreground mb-3 text-xs">
        Used to clone your chezmoi repo and project repositories. Chezmoi manages additional credentials.
      </p>
      <div class="space-y-3">
        <div>
          <label for="{idPrefix}git-host" class="mb-1.5 block text-sm font-medium">Host</label>
          <input
            id="{idPrefix}git-host"
            type="text"
            value={getValue('git.credential.host')}
            onchange={(e) => {
              setValue('git.credential.host', e.currentTarget.value.trim());
            }}
            disabled={isDisabled('git.credential')}
            placeholder="github.com"
            class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                   py-2 text-base focus:ring-3 focus:outline-none
                   disabled:cursor-not-allowed disabled:opacity-50"
          />
        </div>
        <div>
          <label for="{idPrefix}git-username" class="mb-1.5 block text-sm font-medium">Username</label>
          <input
            id="{idPrefix}git-username"
            type="text"
            value={getValue('git.credential.username')}
            onchange={(e) => {
              setValue('git.credential.username', e.currentTarget.value.trim());
            }}
            disabled={isDisabled('git.credential')}
            placeholder="username"
            class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                   py-2 text-base focus:ring-3 focus:outline-none
                   disabled:cursor-not-allowed disabled:opacity-50"
          />
        </div>
        <div>
          <label for="{idPrefix}git-token" class="mb-1.5 block text-sm font-medium">Token</label>
          <input
            id="{idPrefix}git-token"
            type="password"
            value={getValue('git.credential.token')}
            onchange={(e) => {
              setValue('git.credential.token', e.currentTarget.value.trim());
            }}
            disabled={isDisabled('git.credential')}
            placeholder="ghp_..."
            class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                   py-2 text-base focus:ring-3 focus:outline-none
                   disabled:cursor-not-allowed disabled:opacity-50"
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
          onchange={() => {
            toggle('hetzner.serverType');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}server-type" class="mb-1.5 block text-sm font-medium">Server Type</label>
        <select
          id="{idPrefix}server-type"
          value={getValue('hetzner.serverType')}
          onchange={(e) => {
            setValue('hetzner.serverType', e.currentTarget.value);
          }}
          disabled={isDisabled('hetzner.serverType')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {#if serversStore.serverTypes.length === 0}
            <option value={getValue('hetzner.serverType')}>{getValue('hetzner.serverType')}</option>
          {:else}
            {#each serversStore.serverTypes as type (type.name)}
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
          onchange={() => {
            toggle('hetzner.location');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}location" class="mb-1.5 block text-sm font-medium">Location</label>
        <select
          id="{idPrefix}location"
          value={getValue('hetzner.location')}
          onchange={(e) => {
            setValue('hetzner.location', e.currentTarget.value);
          }}
          disabled={isDisabled('hetzner.location')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {#if serversStore.locations.length === 0}
            <option value={getValue('hetzner.location')}>{getValue('hetzner.location')}</option>
          {:else}
            {#each serversStore.locations as loc (loc.name)}
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
          onchange={() => {
            toggle('hetzner.baseImage');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}base-image" class="mb-1.5 block text-sm font-medium">Base Image</label>
        <select
          id="{idPrefix}base-image"
          value={getValue('hetzner.baseImage')}
          onchange={(e) => {
            setValue('hetzner.baseImage', e.currentTarget.value);
          }}
          disabled={isDisabled('hetzner.baseImage')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {#if serversStore.images.length === 0}
            <option value={getValue('hetzner.baseImage')}>{getValue('hetzner.baseImage')}</option>
          {:else}
            {#each serversStore.images as img (img.name)}
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
          onchange={() => {
            toggle('services.dnsService');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}dns-service" class="mb-1.5 block text-sm font-medium">DNS Service</label>
        <select
          id="{idPrefix}dns-service"
          value={getValue('services.dnsService')}
          onchange={(e) => {
            setValue('services.dnsService', e.currentTarget.value);
          }}
          disabled={isDisabled('services.dnsService')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {#each dnsServices as dns (dns.value)}
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
            onchange={() => {
              toggle('services.customDnsDomain');
            }}
            class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
          />
        {/if}
        <div class="flex-1">
          <label for="{idPrefix}custom-dns-domain" class="mb-1.5 block text-sm font-medium">Custom Domain</label>
          <input
            id="{idPrefix}custom-dns-domain"
            type="text"
            value={getValue('services.customDnsDomain')}
            onchange={(e) => {
              setValue('services.customDnsDomain', e.currentTarget.value.trim().toLowerCase());
            }}
            disabled={isDisabled('services.customDnsDomain')}
            placeholder="dev.example.com"
            required
            pattern="[a-z0-9][a-z0-9\.\-]*[a-z0-9]\.[a-z]&#123;2,&#125;"
            class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                   py-2 text-base focus:ring-3 focus:outline-none
                   disabled:cursor-not-allowed disabled:opacity-50"
          />
          <p class="text-muted-foreground mt-1.5 text-sm">
            Delegate this domain to sslip.io nameservers:
            <code class="bg-muted rounded px-1 py-0.5 text-xs">ns-aws.sslip.io</code>,
            <code class="bg-muted rounded px-1 py-0.5 text-xs">ns-azure.sslip.io</code>,
            <code class="bg-muted rounded px-1 py-0.5 text-xs">ns-gce.sslip.io</code>
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
          onchange={() => {
            toggle('services.acmeProvider');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}acme-provider" class="mb-1.5 block text-sm font-medium">ACME Provider</label>
        <select
          id="{idPrefix}acme-provider"
          value={getValue('services.acmeProvider')}
          onchange={(e) => {
            setValue('services.acmeProvider', e.currentTarget.value);
          }}
          disabled={isDisabled('services.acmeProvider')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {#each acmeProviders as provider (provider.value)}
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
          onchange={() => {
            toggle('services.acmeEmail');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}acme-email" class="mb-1.5 block text-sm font-medium">ACME Email (optional)</label>
        <input
          id="{idPrefix}acme-email"
          type="email"
          value={getValue('services.acmeEmail')}
          onchange={(e) => {
            setValue('services.acmeEmail', e.currentTarget.value);
          }}
          disabled={isDisabled('services.acmeEmail')}
          placeholder="admin@example.com"
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        />
        <p class="text-muted-foreground mt-1 text-xs">For Let's Encrypt certificates</p>
      </div>
    </div>

    <!-- ZeroSSL EAB Credentials -->
    {#if getValue('services.acmeProvider') === 'zerossl'}
      <div class="bg-muted/30 space-y-4 rounded-md p-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.zerosslEabKeyId')}
              onchange={() => {
                toggle('services.zerosslEabKeyId');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}zerossl-key-id" class="mb-1.5 block text-sm font-medium">ZeroSSL EAB Key ID</label>
            <input
              id="{idPrefix}zerossl-key-id"
              type="text"
              value={getValue('services.zerosslEabKeyId')}
              onchange={(e) => {
                setValue('services.zerosslEabKeyId', e.currentTarget.value);
              }}
              disabled={isDisabled('services.zerosslEabKeyId')}
              placeholder="From zerossl.com/acme"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.zerosslEabKey')}
              onchange={() => {
                toggle('services.zerosslEabKey');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}zerossl-hmac" class="mb-1.5 block text-sm font-medium">ZeroSSL EAB HMAC Key</label>
            <input
              id="{idPrefix}zerossl-hmac"
              type="password"
              value={getValue('services.zerosslEabKey')}
              onchange={(e) => {
                setValue('services.zerosslEabKey', e.currentTarget.value);
              }}
              disabled={isDisabled('services.zerosslEabKey')}
              placeholder="From zerossl.com/acme"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
      </div>
    {/if}

    <!-- Actalis EAB Credentials -->
    {#if getValue('services.acmeProvider') === 'actalis'}
      <div class="bg-muted/30 space-y-4 rounded-md p-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.actalisEabKeyId')}
              onchange={() => {
                toggle('services.actalisEabKeyId');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}actalis-key-id" class="mb-1.5 block text-sm font-medium">Actalis EAB Key ID</label>
            <input
              id="{idPrefix}actalis-key-id"
              type="text"
              value={getValue('services.actalisEabKeyId')}
              onchange={(e) => {
                setValue('services.actalisEabKeyId', e.currentTarget.value);
              }}
              disabled={isDisabled('services.actalisEabKeyId')}
              placeholder="From Actalis ACME dashboard"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.actalisEabKey')}
              onchange={() => {
                toggle('services.actalisEabKey');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}actalis-hmac" class="mb-1.5 block text-sm font-medium">Actalis EAB HMAC Key</label>
            <input
              id="{idPrefix}actalis-hmac"
              type="password"
              value={getValue('services.actalisEabKey')}
              onchange={(e) => {
                setValue('services.actalisEabKey', e.currentTarget.value);
              }}
              disabled={isDisabled('services.actalisEabKey')}
              placeholder="From Actalis ACME dashboard"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
      </div>
    {/if}

    <!-- Custom ACME Credentials -->
    {#if getValue('services.acmeProvider') === 'custom'}
      <div class="bg-muted/30 space-y-4 rounded-md p-4 {mode === 'profile' ? 'ml-8' : ''}">
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customAcmeUrl')}
              onchange={() => {
                toggle('services.customAcmeUrl');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-acme-url" class="mb-1.5 block text-sm font-medium"
              >Custom ACME Directory URL</label
            >
            <input
              id="{idPrefix}custom-acme-url"
              type="url"
              value={getValue('services.customAcmeUrl')}
              onchange={(e) => {
                setValue('services.customAcmeUrl', e.currentTarget.value);
              }}
              disabled={isDisabled('services.customAcmeUrl')}
              placeholder="https://acme.example.com/directory"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customEabKeyId')}
              onchange={() => {
                toggle('services.customEabKeyId');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-key-id" class="mb-1.5 block text-sm font-medium">EAB Key ID (optional)</label>
            <input
              id="{idPrefix}custom-key-id"
              type="text"
              value={getValue('services.customEabKeyId')}
              onchange={(e) => {
                setValue('services.customEabKeyId', e.currentTarget.value);
              }}
              disabled={isDisabled('services.customEabKeyId')}
              placeholder="Leave empty if not required"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
        <div class="flex items-start gap-3">
          {#if mode === 'profile'}
            <input
              type="checkbox"
              checked={hasOverride('services.customEabKey')}
              onchange={() => {
                toggle('services.customEabKey');
              }}
              class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
            />
          {/if}
          <div class="flex-1">
            <label for="{idPrefix}custom-hmac" class="mb-1.5 block text-sm font-medium">EAB HMAC Key (optional)</label>
            <input
              id="{idPrefix}custom-hmac"
              type="password"
              value={getValue('services.customEabKey')}
              onchange={(e) => {
                setValue('services.customEabKey', e.currentTarget.value);
              }}
              disabled={isDisabled('services.customEabKey')}
              placeholder="Leave empty if not required"
              class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                     py-2 text-base focus:ring-3 focus:outline-none
                     disabled:cursor-not-allowed disabled:opacity-50"
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
          onchange={() => {
            toggle('autoDelete.enabled');
          }}
          class="border-border text-primary focus:ring-focus bg-background h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <label class="flex flex-1 cursor-pointer items-center gap-3">
        <input
          type="checkbox"
          checked={getValue('autoDelete.enabled') as boolean}
          onchange={(e) => {
            setValue('autoDelete.enabled', e.currentTarget.checked);
          }}
          disabled={isDisabled('autoDelete.enabled')}
          class="border-border text-primary focus:ring-focus bg-background h-5 w-5 cursor-pointer rounded border-2 focus:ring-3
                 disabled:cursor-not-allowed disabled:opacity-50"
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
          onchange={() => {
            toggle('autoDelete.timeoutMinutes');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}timeout" class="mb-1.5 block text-sm font-medium">Timeout (minutes)</label>
        <input
          id="{idPrefix}timeout"
          type="number"
          value={getValue('autoDelete.timeoutMinutes')}
          onchange={(e) => {
            setValue('autoDelete.timeoutMinutes', Number.parseInt(e.currentTarget.value) || 0);
          }}
          disabled={isDisabled('autoDelete.timeoutMinutes')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        />
      </div>
    </div>

    <!-- Warning Minutes -->
    <div class="flex items-start gap-3">
      {#if mode === 'profile'}
        <input
          type="checkbox"
          checked={hasOverride('autoDelete.warningMinutes')}
          onchange={() => {
            toggle('autoDelete.warningMinutes');
          }}
          class="border-border text-primary focus:ring-focus bg-background mt-3 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
        />
      {/if}
      <div class="flex-1">
        <label for="{idPrefix}warning" class="mb-1.5 block text-sm font-medium">Warning (minutes before)</label>
        <input
          id="{idPrefix}warning"
          type="number"
          value={getValue('autoDelete.warningMinutes')}
          onchange={(e) => {
            setValue('autoDelete.warningMinutes', Number.parseInt(e.currentTarget.value) || 0);
          }}
          disabled={isDisabled('autoDelete.warningMinutes')}
          class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
                 py-2 text-base focus:ring-3 focus:outline-none
                 disabled:cursor-not-allowed disabled:opacity-50"
        />
      </div>
    </div>
  </div>
</Card>

<!-- Custom Cloud-Init -->
<Card title="Custom Cloud-Init">
  {#if mode === 'profile'}
    <div class="mb-4 flex items-start gap-3">
      <input
        type="checkbox"
        checked={hasOverride('customCloudInit')}
        onchange={() => {
          toggle('customCloudInit');
        }}
        class="border-border text-primary focus:ring-focus bg-background mt-1 h-5 w-5 cursor-pointer rounded border-2 focus:ring-3"
      />
      <p class="text-muted-foreground text-sm">Override custom cloud-init for this profile</p>
    </div>
  {/if}

  {#if mode === 'global' || hasOverride('customCloudInit')}
    <CustomCloudInitEditor {getValue} {setValue} {isDisabled} {idPrefix} />
  {:else}
    <p class="text-muted-foreground text-sm">Using global custom cloud-init configuration.</p>
  {/if}
</Card>
