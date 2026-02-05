<script lang="ts">
  import { serversStore } from '$lib/stores/servers.svelte';
  import { getMiseToolOptions, getAptPackageOptions } from '$lib/data/packages';
  import { shellOptions, dnsServices, acmeProviders } from '$lib/data/options';
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
  }

  let { mode, isOverridden, toggleOverride, getValue, setValue, idPrefix = '' }: Props = $props();

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
</script>

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
