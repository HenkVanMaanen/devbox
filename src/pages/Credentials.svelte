<script lang="ts">
  import FloatingActions from '$components/FloatingActions.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import Input from '$components/ui/Input.svelte';
  import Modal from '$components/ui/Modal.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import { clearAll } from '$lib/utils/storage';

  let snapshot = $state(credentialsStore.token);
  let dirty = $derived(credentialsStore.token !== snapshot);
  let clearAllModal = $state(false);

  function save() {
    credentialsStore.save();
    snapshot = credentialsStore.token;
    serversStore.clearOptions();
    void serversStore.load(credentialsStore.token);
    toast.success('API token saved');
  }

  function discard() {
    credentialsStore.token = snapshot;
    toast.info('Changes discarded');
  }

  async function validate() {
    const valid = await credentialsStore.validate();
    if (valid) {
      toast.success('Token is valid!');
    } else {
      toast.error('Token is invalid');
    }
  }

  function confirmClearAll() {
    clearAll();
    // Reset stores to defaults
    credentialsStore.token = '';
    credentialsStore.save();
    configStore.reset();
    // Reload the page to reset all state
    window.location.reload();
  }
</script>

<div class="space-y-6 pb-24">
  <h1 class="text-2xl font-bold">API Token</h1>

  <Card
    title="Hetzner Cloud API"
    description="Your API token is stored locally and never sent to any server except Hetzner."
  >
    <div class="space-y-4">
      <Input
        label="API Token"
        type="password"
        bind:value={credentialsStore.token}
        placeholder="Enter your Hetzner API token"
        help="Get your token from the Hetzner Cloud Console → Security → API Tokens"
      />

      <div class="flex gap-3">
        <Button variant="secondary" onclick={validate} loading={credentialsStore.validating}>Validate Token</Button>
      </div>
    </div>
  </Card>

  <Card title="Danger Zone" description="Destructive actions that cannot be undone.">
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <p class="font-medium">Clear All Data</p>
          <p class="text-muted-foreground text-sm">
            Remove all configuration, profiles, and credentials from this browser.
          </p>
        </div>
        <Button variant="destructive" onclick={() => (clearAllModal = true)}>Clear All Data</Button>
      </div>
    </div>
  </Card>
</div>

<Modal bind:open={clearAllModal} title="Clear All Data" onClose={() => (clearAllModal = false)}>
  <p>Are you sure you want to clear all data? This will remove:</p>
  <ul class="text-muted-foreground mt-2 list-inside list-disc">
    <li>Hetzner API token</li>
    <li>All profiles and configuration</li>
    <li>Server access tokens</li>
    <li>Theme preferences</li>
  </ul>
  <p class="text-destructive mt-3 font-medium">This action cannot be undone.</p>

  {#snippet actions()}
    <Button variant="secondary" onclick={() => (clearAllModal = false)}>Cancel</Button>
    <Button variant="destructive" onclick={confirmClearAll}>Clear All Data</Button>
  {/snippet}
</Modal>

{#if dirty}
  <FloatingActions onSave={save} onDiscard={discard} />
{/if}
