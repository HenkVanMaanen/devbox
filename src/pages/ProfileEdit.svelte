<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clone } from '$lib/utils/storage';
  import { getMiseToolOptions, getAptPackageOptions } from '$lib/data/packages';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Input from '$components/ui/Input.svelte';

  interface Props {
    profileId: string;
  }

  let { profileId }: Props = $props();

  let profile = $derived(profilesStore.profiles[profileId]);

  // Load Hetzner options for dropdowns
  $effect(() => {
    if (credentialsStore.hasToken) {
      serversStore.loadOptions(credentialsStore.token);
    }
  });

  // Helper to check if a path is overridden
  function isOverridden(path: string): boolean {
    return profile ? path in profile.overrides : false;
  }

  // Helper to get value (override or global)
  function getValue<T>(path: string): T {
    if (profile && path in profile.overrides) {
      return profile.overrides[path] as T;
    }
    // Get from global config
    const keys = path.split('.');
    let current: unknown = configStore.value;
    for (const key of keys) {
      current = (current as Record<string, unknown>)[key];
    }
    return current as T;
  }

  // Helper to set override value
  function setValue(path: string, value: unknown) {
    if (!profile) return;
    profile.overrides[path] = value;
    profilesStore.save();
  }

  // Toggle override on/off
  function toggleOverride(path: string) {
    if (!profile) return;
    if (path in profile.overrides) {
      delete profile.overrides[path];
    } else {
      // Copy current global value as initial override
      const keys = path.split('.');
      let current: unknown = configStore.value;
      for (const key of keys) {
        current = (current as Record<string, unknown>)[key];
      }
      profile.overrides[path] = clone(current);
    }
    profilesStore.save();
  }

  function goBack() {
    window.location.hash = 'profiles';
  }

  // Options for dropdowns
  const shellOptions = [
    { value: 'fish', label: 'Fish', description: 'Modern, user-friendly shell' },
    { value: 'zsh', label: 'Zsh', description: 'Extended Bourne shell' },
    { value: 'bash', label: 'Bash', description: 'GNU Bourne-Again shell' },
  ];

  const dnsServices = [
    { value: 'sslip.io', label: 'sslip.io', description: 'Wildcard DNS for any IP' },
    { value: 'nip.io', label: 'nip.io', description: 'Dead simple wildcard DNS' },
  ];

  const acmeProviders = [
    { value: 'zerossl', label: 'ZeroSSL', description: 'No rate limits' },
    { value: 'letsencrypt', label: "Let's Encrypt", description: 'Most popular CA' },
    { value: 'buypass', label: 'Buypass', description: 'Norwegian CA' },
    { value: 'actalis', label: 'Actalis', description: 'Italian CA' },
    { value: 'custom', label: 'Custom ACME', description: 'Self-hosted or other CA' },
  ];

  const miseOptions = getMiseToolOptions();
  const aptOptions = getAptPackageOptions();

  // Package filters
  let miseToolFilter = $state('');
  let aptPackageFilter = $state('');

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
    const current = getValue<string[]>('packages.mise');
    if (current.includes(tool)) {
      setValue('packages.mise', current.filter((t) => t !== tool));
    } else {
      setValue('packages.mise', [...current, tool]);
    }
  }

  function toggleAptPackage(pkg: string) {
    const current = getValue<string[]>('packages.apt');
    if (current.includes(pkg)) {
      setValue('packages.apt', current.filter((p) => p !== pkg));
    } else {
      setValue('packages.apt', [...current, pkg]);
    }
  }
</script>

{#if !profile}
  <div class="text-center py-8">
    <p class="text-muted-foreground mb-4">Profile not found.</p>
    <Button onclick={goBack}>Back to Profiles</Button>
  </div>
{:else}
  <div class="space-y-6 pb-24">
    <div class="flex items-center justify-between">
      <div>
        <Button variant="ghost" size="sm" onclick={goBack}>&larr; Back</Button>
        <h1 class="text-2xl font-bold mt-2">Edit: {profile.name}</h1>
        <p class="text-muted-foreground">Enable overrides to customize settings for this profile.</p>
      </div>
    </div>

    <!-- Hetzner Settings -->
    <Card title="Hetzner Settings">
      <div class="space-y-4">
        <!-- Server Type -->
        <div class="flex items-start gap-3">
          <input
            type="checkbox"
            checked={isOverridden('hetzner.serverType')}
            onchange={() => toggleOverride('hetzner.serverType')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">Server Type</label>
            <select
              value={getValue('hetzner.serverType')}
              onchange={(e) => setValue('hetzner.serverType', e.currentTarget.value)}
              disabled={!isOverridden('hetzner.serverType')}
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
          <input
            type="checkbox"
            checked={isOverridden('hetzner.location')}
            onchange={() => toggleOverride('hetzner.location')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">Location</label>
            <select
              value={getValue('hetzner.location')}
              onchange={(e) => setValue('hetzner.location', e.currentTarget.value)}
              disabled={!isOverridden('hetzner.location')}
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
          <input
            type="checkbox"
            checked={isOverridden('hetzner.baseImage')}
            onchange={() => toggleOverride('hetzner.baseImage')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">Base Image</label>
            <select
              value={getValue('hetzner.baseImage')}
              onchange={(e) => setValue('hetzner.baseImage', e.currentTarget.value)}
              disabled={!isOverridden('hetzner.baseImage')}
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
          <input
            type="checkbox"
            checked={isOverridden('shell.default')}
            onchange={() => toggleOverride('shell.default')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">Default Shell</label>
            <select
              value={getValue('shell.default')}
              onchange={(e) => setValue('shell.default', e.currentTarget.value)}
              disabled={!isOverridden('shell.default')}
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
          <input
            type="checkbox"
            checked={isOverridden('shell.starship')}
            onchange={() => toggleOverride('shell.starship')}
            class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <label class="flex items-center gap-3 cursor-pointer flex-1">
            <input
              type="checkbox"
              checked={getValue('shell.starship')}
              onchange={(e) => setValue('shell.starship', e.currentTarget.checked)}
              disabled={!isOverridden('shell.starship')}
              class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <span class={!isOverridden('shell.starship') ? 'opacity-50' : ''}>Enable Starship prompt</span>
          </label>
        </div>
      </div>
    </Card>

    <!-- Services -->
    <Card title="Services">
      <div class="space-y-4">
        <!-- VS Code Server -->
        <div class="flex items-center gap-3">
          <input
            type="checkbox"
            checked={isOverridden('services.codeServer')}
            onchange={() => toggleOverride('services.codeServer')}
            class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <label class="flex items-center gap-3 cursor-pointer flex-1">
            <input
              type="checkbox"
              checked={getValue('services.codeServer')}
              onchange={(e) => setValue('services.codeServer', e.currentTarget.checked)}
              disabled={!isOverridden('services.codeServer')}
              class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <span class={!isOverridden('services.codeServer') ? 'opacity-50' : ''}>VS Code Server</span>
          </label>
        </div>

        <!-- Claude Terminal -->
        <div class="flex items-center gap-3">
          <input
            type="checkbox"
            checked={isOverridden('services.claudeTerminal')}
            onchange={() => toggleOverride('services.claudeTerminal')}
            class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <label class="flex items-center gap-3 cursor-pointer flex-1">
            <input
              type="checkbox"
              checked={getValue('services.claudeTerminal')}
              onchange={(e) => setValue('services.claudeTerminal', e.currentTarget.checked)}
              disabled={!isOverridden('services.claudeTerminal')}
              class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <span class={!isOverridden('services.claudeTerminal') ? 'opacity-50' : ''}>Claude Terminal</span>
          </label>
        </div>

        <!-- Shell Terminal -->
        <div class="flex items-center gap-3">
          <input
            type="checkbox"
            checked={isOverridden('services.shellTerminal')}
            onchange={() => toggleOverride('services.shellTerminal')}
            class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <label class="flex items-center gap-3 cursor-pointer flex-1">
            <input
              type="checkbox"
              checked={getValue('services.shellTerminal')}
              onchange={(e) => setValue('services.shellTerminal', e.currentTarget.checked)}
              disabled={!isOverridden('services.shellTerminal')}
              class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <span class={!isOverridden('services.shellTerminal') ? 'opacity-50' : ''}>Shell Terminal</span>
          </label>
        </div>

        <!-- DNS Service -->
        <div class="flex items-start gap-3">
          <input
            type="checkbox"
            checked={isOverridden('services.dnsService')}
            onchange={() => toggleOverride('services.dnsService')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">DNS Service</label>
            <select
              value={getValue('services.dnsService')}
              onchange={(e) => setValue('services.dnsService', e.currentTarget.value)}
              disabled={!isOverridden('services.dnsService')}
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
          <input
            type="checkbox"
            checked={isOverridden('services.acmeProvider')}
            onchange={() => toggleOverride('services.acmeProvider')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">ACME Provider</label>
            <select
              value={getValue('services.acmeProvider')}
              onchange={(e) => setValue('services.acmeProvider', e.currentTarget.value)}
              disabled={!isOverridden('services.acmeProvider')}
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
      </div>
    </Card>

    <!-- Auto-Delete -->
    <Card title="Auto-Delete">
      <div class="space-y-4">
        <!-- Enabled -->
        <div class="flex items-center gap-3">
          <input
            type="checkbox"
            checked={isOverridden('autoDelete.enabled')}
            onchange={() => toggleOverride('autoDelete.enabled')}
            class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <label class="flex items-center gap-3 cursor-pointer flex-1">
            <input
              type="checkbox"
              checked={getValue('autoDelete.enabled')}
              onchange={(e) => setValue('autoDelete.enabled', e.currentTarget.checked)}
              disabled={!isOverridden('autoDelete.enabled')}
              class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer
                     disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <span class={!isOverridden('autoDelete.enabled') ? 'opacity-50' : ''}>Enable auto-delete for idle servers</span>
          </label>
        </div>

        <!-- Timeout -->
        <div class="flex items-start gap-3">
          <input
            type="checkbox"
            checked={isOverridden('autoDelete.timeoutMinutes')}
            onchange={() => toggleOverride('autoDelete.timeoutMinutes')}
            class="mt-3 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
          />
          <div class="flex-1">
            <label class="block text-sm font-medium mb-1.5">Timeout (minutes)</label>
            <input
              type="number"
              value={getValue('autoDelete.timeoutMinutes')}
              onchange={(e) => setValue('autoDelete.timeoutMinutes', parseInt(e.currentTarget.value) || 0)}
              disabled={!isOverridden('autoDelete.timeoutMinutes')}
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
      <div class="flex items-start gap-3 mb-4">
        <input
          type="checkbox"
          checked={isOverridden('packages.mise')}
          onchange={() => toggleOverride('packages.mise')}
          class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
        <p class="text-sm text-muted-foreground">Override mise tools for this profile</p>
      </div>

      {#if isOverridden('packages.mise')}
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
      {:else}
        <p class="text-sm text-muted-foreground">Using global mise tools configuration.</p>
      {/if}
    </Card>

    <!-- Packages - APT -->
    <Card title="Packages - APT">
      <div class="flex items-start gap-3 mb-4">
        <input
          type="checkbox"
          checked={isOverridden('packages.apt')}
          onchange={() => toggleOverride('packages.apt')}
          class="mt-1 w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
        />
        <p class="text-sm text-muted-foreground">Override APT packages for this profile</p>
      </div>

      {#if isOverridden('packages.apt')}
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
      {:else}
        <p class="text-sm text-muted-foreground">Using global APT packages configuration.</p>
      {/if}
    </Card>
  </div>
{/if}
