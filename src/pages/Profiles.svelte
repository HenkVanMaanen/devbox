<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Input from '$components/ui/Input.svelte';
  import Modal from '$components/ui/Modal.svelte';

  // New profile form
  let newProfileName = $state('');
  let showCreateModal = $state(false);

  // Duplicate modal
  let showDuplicateModal = $state(false);
  let duplicateSourceId = $state('');
  let duplicateNewName = $state('');

  // Edit modal
  let showEditModal = $state(false);
  let editingProfileId = $state('');
  let editingProfile = $derived(editingProfileId ? profilesStore.profiles[editingProfileId] : undefined);

  // Delete confirmation
  let showDeleteModal = $state(false);
  let deletingProfileId = $state('');
  let deletingProfile = $derived(deletingProfileId ? profilesStore.profiles[deletingProfileId] : undefined);

  // Available override paths (config sections that can be overridden per-profile)
  const overridePaths = [
    { path: 'hetzner.serverType', label: 'Server Type', section: 'Hetzner' },
    { path: 'hetzner.location', label: 'Location', section: 'Hetzner' },
    { path: 'hetzner.baseImage', label: 'Base Image', section: 'Hetzner' },
    { path: 'services.codeServer', label: 'VS Code Server', section: 'Services' },
    { path: 'services.claudeTerminal', label: 'Claude Terminal', section: 'Services' },
    { path: 'services.shellTerminal', label: 'Shell Terminal', section: 'Services' },
    { path: 'shell.starship', label: 'Starship Prompt', section: 'Shell' },
    { path: 'autoDelete.enabled', label: 'Auto-Delete', section: 'Auto-Delete' },
    { path: 'autoDelete.timeoutMinutes', label: 'Timeout (minutes)', section: 'Auto-Delete' },
  ];

  function createProfile() {
    if (!newProfileName.trim()) {
      toast.error('Please enter a profile name');
      return;
    }
    const id = profilesStore.create(newProfileName.trim());
    toast.success(`Profile "${newProfileName}" created`);
    newProfileName = '';
    showCreateModal = false;
    // Open edit modal for the new profile
    editingProfileId = id;
    showEditModal = true;
  }

  function openDuplicateModal(sourceId: string) {
    const source = profilesStore.get(sourceId);
    if (source) {
      duplicateSourceId = sourceId;
      duplicateNewName = `${source.name} (copy)`;
      showDuplicateModal = true;
    }
  }

  function duplicateProfile() {
    if (!duplicateNewName.trim()) {
      toast.error('Please enter a name for the duplicate');
      return;
    }
    profilesStore.duplicate(duplicateSourceId, duplicateNewName.trim());
    toast.success(`Profile duplicated as "${duplicateNewName}"`);
    duplicateNewName = '';
    duplicateSourceId = '';
    showDuplicateModal = false;
  }

  function openEditModal(profileId: string) {
    editingProfileId = profileId;
    showEditModal = true;
  }

  function openDeleteModal(profileId: string) {
    deletingProfileId = profileId;
    showDeleteModal = true;
  }

  function deleteProfile() {
    if (deletingProfile) {
      const name = deletingProfile.name;
      profilesStore.delete(deletingProfileId);
      toast.success(`Profile "${name}" deleted`);
    }
    deletingProfileId = '';
    showDeleteModal = false;
  }

  function setDefault(profileId: string | null) {
    profilesStore.setDefault(profileId);
    toast.success(profileId ? 'Default profile set' : 'Default profile cleared');
  }

  function toggleOverride(profileId: string, path: string) {
    const profile = profilesStore.get(profileId);
    if (!profile) return;

    if (path in profile.overrides) {
      profilesStore.disableOverride(profileId, path);
    } else {
      profilesStore.enableOverride(profileId, path);
    }
  }

  function getOverrideValue(profileId: string, path: string): unknown {
    const profile = profilesStore.get(profileId);
    if (!profile || !(path in profile.overrides)) {
      return configStore.get(path);
    }
    return profile.overrides[path];
  }

  function setOverrideValue(profileId: string, path: string, value: unknown) {
    const profile = profilesStore.get(profileId);
    if (!profile) return;
    profile.overrides[path] = value;
    profilesStore.save();
  }

  function formatValue(value: unknown): string {
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (value === null || value === undefined) return '-';
    return String(value);
  }
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold">Profiles</h1>
    <Button onclick={() => (showCreateModal = true)}>New Profile</Button>
  </div>

  <p class="text-muted-foreground">
    Profiles let you override global settings for different use cases. Create profiles for different projects,
    server sizes, or configurations.
  </p>

  {#if profilesStore.profileList.length === 0}
    <Card>
      <div class="text-center py-8">
        <p class="text-muted-foreground mb-4">No profiles yet. Create one to get started.</p>
        <Button onclick={() => (showCreateModal = true)}>Create Your First Profile</Button>
      </div>
    </Card>
  {:else}
    <div class="space-y-4">
      {#each profilesStore.profileList as profile (profile.id)}
        <Card>
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div>
                <h3 class="font-semibold text-lg">{profile.name}</h3>
                <p class="text-sm text-muted-foreground">
                  {Object.keys(profile.overrides).length} override{Object.keys(profile.overrides).length !== 1 ? 's' : ''}
                  {#if profilesStore.defaultProfileId === profile.id}
                    <span class="ml-2 px-2 py-0.5 bg-primary/20 text-primary rounded text-xs font-medium">Default</span>
                  {/if}
                </p>
              </div>
            </div>
            <div class="flex items-center gap-2">
              {#if profilesStore.defaultProfileId !== profile.id}
                <Button variant="ghost" size="sm" onclick={() => setDefault(profile.id)}>Set Default</Button>
              {:else}
                <Button variant="ghost" size="sm" onclick={() => setDefault(null)}>Clear Default</Button>
              {/if}
              <Button variant="secondary" size="sm" onclick={() => openEditModal(profile.id)}>Edit</Button>
              <Button variant="ghost" size="sm" onclick={() => openDuplicateModal(profile.id)}>Duplicate</Button>
              <Button variant="destructive" size="sm" onclick={() => openDeleteModal(profile.id)}>Delete</Button>
            </div>
          </div>

          {#if Object.keys(profile.overrides).length > 0}
            <div class="mt-4 pt-4 border-t border-border">
              <p class="text-sm font-medium text-muted-foreground mb-2">Overrides:</p>
              <div class="flex flex-wrap gap-2">
                {#each Object.entries(profile.overrides) as [path, value]}
                  {@const override = overridePaths.find((o) => o.path === path)}
                  <span class="px-2 py-1 bg-muted rounded text-sm">
                    {override?.label ?? path}: {formatValue(value)}
                  </span>
                {/each}
              </div>
            </div>
          {/if}
        </Card>
      {/each}
    </div>
  {/if}
</div>

<!-- Create Profile Modal -->
<Modal bind:open={showCreateModal} title="Create Profile" onClose={() => (showCreateModal = false)}>
  <div class="space-y-4">
    <Input label="Profile Name" bind:value={newProfileName} placeholder="My Project" />
  </div>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (showCreateModal = false)}>Cancel</Button>
    <Button onclick={createProfile}>Create</Button>
  {/snippet}
</Modal>

<!-- Duplicate Profile Modal -->
<Modal bind:open={showDuplicateModal} title="Duplicate Profile" onClose={() => (showDuplicateModal = false)}>
  <div class="space-y-4">
    <Input label="New Profile Name" bind:value={duplicateNewName} placeholder="Profile name" />
  </div>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (showDuplicateModal = false)}>Cancel</Button>
    <Button onclick={duplicateProfile}>Duplicate</Button>
  {/snippet}
</Modal>

<!-- Edit Profile Modal -->
<Modal bind:open={showEditModal} title={editingProfile ? `Edit: ${editingProfile.name}` : 'Edit Profile'} onClose={() => (showEditModal = false)}>
  {#if editingProfile}
    <div class="space-y-6 max-h-[60vh] overflow-y-auto">
      <p class="text-sm text-muted-foreground">
        Enable overrides to customize settings for this profile. Disabled items use global settings.
      </p>

      {#each ['Hetzner', 'Services', 'Shell', 'Auto-Delete'] as section}
        <div>
          <h4 class="font-medium mb-3">{section}</h4>
          <div class="space-y-3">
            {#each overridePaths.filter((o) => o.section === section) as override}
              {@const isEnabled = override.path in editingProfile.overrides}
              {@const currentValue = getOverrideValue(editingProfileId, override.path)}
              <div class="flex items-center justify-between p-3 bg-muted/50 rounded-md">
                <div class="flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={isEnabled}
                    onchange={() => toggleOverride(editingProfileId, override.path)}
                    class="w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer"
                  />
                  <span class={isEnabled ? 'font-medium' : 'text-muted-foreground'}>{override.label}</span>
                </div>
                {#if isEnabled}
                  {#if typeof currentValue === 'boolean'}
                    <select
                      value={currentValue ? 'true' : 'false'}
                      onchange={(e) => setOverrideValue(editingProfileId, override.path, e.currentTarget.value === 'true')}
                      class="px-3 py-1.5 bg-background border-2 border-border rounded-md focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
                    >
                      <option value="true">Yes</option>
                      <option value="false">No</option>
                    </select>
                  {:else if typeof currentValue === 'number'}
                    <input
                      type="number"
                      value={currentValue}
                      onchange={(e) => setOverrideValue(editingProfileId, override.path, parseInt(e.currentTarget.value) || 0)}
                      class="w-24 px-3 py-1.5 bg-background border-2 border-border rounded-md focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
                    />
                  {:else}
                    <input
                      type="text"
                      value={String(currentValue ?? '')}
                      onchange={(e) => setOverrideValue(editingProfileId, override.path, e.currentTarget.value)}
                      class="w-32 px-3 py-1.5 bg-background border-2 border-border rounded-md focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary"
                    />
                  {/if}
                {:else}
                  <span class="text-sm text-muted-foreground">{formatValue(currentValue)}</span>
                {/if}
              </div>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  {/if}

  {#snippet actions()}
    <Button onclick={() => (showEditModal = false)}>Done</Button>
  {/snippet}
</Modal>

<!-- Delete Confirmation Modal -->
<Modal bind:open={showDeleteModal} title="Delete Profile" onClose={() => (showDeleteModal = false)}>
  <p>
    Are you sure you want to delete <strong>{deletingProfile?.name}</strong>? This action cannot be undone.
  </p>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (showDeleteModal = false)}>Cancel</Button>
    <Button variant="destructive" onclick={deleteProfile}>Delete</Button>
  {/snippet}
</Modal>
