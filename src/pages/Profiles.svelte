<script lang="ts">
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Input from '$components/ui/Input.svelte';
  import Modal from '$components/ui/Modal.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { toast } from '$lib/stores/toast.svelte';

  // New profile form
  let newProfileName = $state('');
  let showCreateModal = $state(false);

  // Duplicate modal
  let showDuplicateModal = $state(false);
  let duplicateSourceId = $state('');
  let duplicateNewName = $state('');

  // Delete confirmation
  let showDeleteModal = $state(false);
  let deletingProfileId = $state('');
  let deletingProfile = $derived(deletingProfileId ? profilesStore.profiles[deletingProfileId] : undefined);

  function createProfile() {
    if (!newProfileName.trim()) {
      toast.error('Please enter a profile name');
      return;
    }
    const id = profilesStore.create(newProfileName.trim());
    toast.success(`Profile "${newProfileName}" created`);
    newProfileName = '';
    showCreateModal = false;
    // Navigate to edit page
    window.location.hash = `profiles/${id}`;
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
    const id = profilesStore.duplicate(duplicateSourceId, duplicateNewName.trim());
    toast.success(`Profile duplicated as "${duplicateNewName}"`);
    duplicateNewName = '';
    duplicateSourceId = '';
    showDuplicateModal = false;
    // Navigate to edit page
    window.location.hash = `profiles/${id}`;
  }

  function editProfile(profileId: string) {
    window.location.hash = `profiles/${profileId}`;
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

  function setDefault(profileId: null | string) {
    profilesStore.setDefault(profileId);
    toast.success(profileId ? 'Default profile set' : 'Default profile cleared');
  }

  function formatValue(value: unknown): string {
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (Array.isArray(value)) return `${value.length} items`;
    if (value === null || value === undefined) return '-';
    if (typeof value === 'object') return JSON.stringify(value);
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return value.toString();
    return '-';
  }

  function formatPath(path: string): string {
    // Convert 'hetzner.serverType' to 'Server Type'
    const parts = path.split('.');
    const last = parts.at(-1) ?? path;
    return last.replaceAll(/([A-Z])/g, ' $1').replace(/^./, (s) => s.toUpperCase());
  }
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold">Profiles</h1>
    <Button onclick={() => (showCreateModal = true)}>New Profile</Button>
  </div>

  <p class="text-muted-foreground">
    Profiles let you override global settings for different use cases. Create profiles for different projects, server
    sizes, or configurations.
  </p>

  {#if profilesStore.profileList.length === 0}
    <Card>
      <div class="py-8 text-center">
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
                <h3 class="text-lg font-semibold">{profile.name}</h3>
                <p class="text-muted-foreground text-sm">
                  {Object.keys(profile.overrides).length} override{Object.keys(profile.overrides).length !== 1
                    ? 's'
                    : ''}
                  {#if profilesStore.defaultProfileId === profile.id}
                    <span class="bg-primary/20 text-primary ml-2 rounded px-2 py-0.5 text-xs font-medium">Default</span>
                  {/if}
                </p>
              </div>
            </div>
            <div class="flex items-center gap-2">
              {#if profilesStore.defaultProfileId !== profile.id}
                <Button
                  variant="ghost"
                  size="sm"
                  onclick={() => {
                    setDefault(profile.id);
                  }}>Set Default</Button
                >
              {:else}
                <Button
                  variant="ghost"
                  size="sm"
                  onclick={() => {
                    setDefault(null);
                  }}>Clear Default</Button
                >
              {/if}
              <Button
                variant="secondary"
                size="sm"
                onclick={() => {
                  editProfile(profile.id);
                }}>Edit</Button
              >
              <Button
                variant="ghost"
                size="sm"
                onclick={() => {
                  openDuplicateModal(profile.id);
                }}>Duplicate</Button
              >
              <Button
                variant="destructive"
                size="sm"
                onclick={() => {
                  openDeleteModal(profile.id);
                }}>Delete</Button
              >
            </div>
          </div>

          {#if Object.keys(profile.overrides).length > 0}
            <div class="border-border mt-4 border-t pt-4">
              <p class="text-muted-foreground mb-2 text-sm font-medium">Overrides:</p>
              <div class="flex flex-wrap gap-2">
                {#each Object.entries(profile.overrides) as [path, value] (path)}
                  <span class="bg-muted rounded px-2 py-1 text-sm">
                    {formatPath(path)}: {formatValue(value)}
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
