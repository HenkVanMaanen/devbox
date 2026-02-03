<script lang="ts">
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { toast } from '$lib/stores/toast.svelte';
  import Input from '$components/ui/Input.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';
  import FloatingActions from '$components/FloatingActions.svelte';

  let snapshot = $state(credentialsStore.token);
  let dirty = $derived(credentialsStore.token !== snapshot);

  function save() {
    credentialsStore.save();
    snapshot = credentialsStore.token;
    serversStore.clearOptions();
    serversStore.load(credentialsStore.token);
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
</script>

<div class="space-y-6 pb-24">
  <h1 class="text-2xl font-bold">API Token</h1>

  <Card title="Hetzner Cloud API" description="Your API token is stored locally and never sent to any server except Hetzner.">
    <div class="space-y-4">
      <Input
        label="API Token"
        type="password"
        bind:value={credentialsStore.token}
        placeholder="Enter your Hetzner API token"
        help="Get your token from the Hetzner Cloud Console → Security → API Tokens"
      />

      <div class="flex gap-3">
        <Button variant="secondary" onclick={validate} loading={credentialsStore.validating}>
          Validate Token
        </Button>
      </div>
    </div>
  </Card>
</div>

{#if dirty}
  <FloatingActions onSave={save} onDiscard={discard} />
{/if}
