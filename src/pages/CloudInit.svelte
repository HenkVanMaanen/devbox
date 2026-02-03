<script lang="ts">
  import { credentialsStore } from '$lib/stores/credentials.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { generateCloudInit } from '$lib/utils/cloudinit';
  import { toast } from '$lib/stores/toast.svelte';
  import Button from '$components/ui/Button.svelte';
  import Card from '$components/ui/Card.svelte';

  // Generate cloud-init script
  const script = $derived.by(() => {
    if (!credentialsStore.hasToken) return '';
    const config = profilesStore.getConfigForProfile();
    return generateCloudInit('devbox-preview', credentialsStore.token, config);
  });

  // Calculate size
  const size = $derived(new Blob([script]).size);
  const sizeKB = $derived((size / 1024).toFixed(1));
  const sizePercent = $derived(Math.round((size / 32768) * 100));
  const sizeColor = $derived(sizePercent > 90 ? 'text-destructive' : sizePercent > 70 ? 'text-warning' : 'text-success');
  const barColor = $derived(sizePercent > 90 ? 'bg-destructive' : sizePercent > 70 ? 'bg-warning' : 'bg-success');

  async function copyToClipboard() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(script);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = script;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      toast.success('Copied to clipboard');
    } catch {
      toast.error('Failed to copy');
    }
  }

  function download() {
    const blob = new Blob([script], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cloud-init.yaml';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Downloaded cloud-init.yaml');
  }
</script>

<div class="space-y-6">
  <h1 class="text-2xl font-bold">Cloud-Init Preview</h1>

  {#if !credentialsStore.hasToken}
    <Card>
      <div class="text-center py-8">
        <h2 class="text-lg font-semibold mb-2">Hetzner Token Required</h2>
        <p class="text-muted-foreground mb-4">Configure your Hetzner API token to preview cloud-init scripts.</p>
        <a href="#credentials" class="inline-flex items-center justify-center px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary-hover">
          Configure API Token
        </a>
      </div>
    </Card>
  {:else}
    <Card>
      <div class="flex items-center justify-between flex-wrap gap-4 mb-4">
        <div>
          <h2 class="text-lg font-semibold">Generated Script</h2>
          <p class="text-sm text-muted-foreground">Preview the cloud-init user-data that will be sent to Hetzner</p>
        </div>
        <div class="flex gap-2">
          <Button variant="secondary" size="sm" onclick={copyToClipboard}>Copy</Button>
          <Button variant="secondary" size="sm" onclick={download}>Download</Button>
        </div>
      </div>

      <div class="mb-4">
        <div class="flex items-center justify-between text-sm mb-1">
          <span>Size</span>
          <span class="{sizeColor} font-medium">{sizeKB} KB / 32 KB ({sizePercent}%)</span>
        </div>
        <div class="h-2 bg-muted rounded-full overflow-hidden">
          <div class="h-full {barColor} transition-all" style="width: {Math.min(sizePercent, 100)}%"></div>
        </div>
        {#if sizePercent > 90}
          <p class="text-xs text-destructive mt-1">Warning: Close to Hetzner's 32KB limit!</p>
        {/if}
      </div>

      <div class="border border-border rounded-md overflow-hidden">
        <pre class="text-xs bg-background p-4 overflow-auto font-mono leading-relaxed max-h-[70vh]"><code>{script}</code></pre>
      </div>
    </Card>
  {/if}
</div>
