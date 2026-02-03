<script lang="ts">
  import type { Server } from '$lib/types';
  import { serversStore } from '$lib/stores/servers.svelte';
  import Button from './ui/Button.svelte';
  import Card from './ui/Card.svelte';
  import { toast } from '$lib/stores/toast.svelte';

  interface Props {
    server: Server;
    onDelete: () => void;
  }

  let { server, onDelete }: Props = $props();

  const accessToken = $derived(serversStore.getServerToken(server.name));
  const baseUrl = $derived(`https://${server.public_net.ipv4.ip}.nip.io`);

  const statusColors: Record<string, string> = {
    running: 'bg-success/30 text-success',
    starting: 'bg-warning/30 text-warning',
    stopping: 'bg-warning/30 text-warning',
    off: 'bg-muted text-muted-foreground',
    initializing: 'bg-primary/30 text-primary',
  };

  async function copyToClipboard(text: string, label: string) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for HTTP
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      toast.success(`${label} copied`);
    } catch {
      toast.error('Failed to copy');
    }
  }
</script>

<Card class="mb-4">
  <div class="flex items-start justify-between">
    <div>
      <h3 class="text-lg font-semibold">{server.name}</h3>
      <div class="flex items-center gap-2 mt-1">
        <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold {statusColors[server.status] ?? statusColors['off']}">
          {server.status}
        </span>
        <span class="text-sm text-muted-foreground">
          {server.server_type.name} &middot; {server.datacenter.location.city}
        </span>
      </div>
    </div>

    <Button variant="destructive" size="sm" onclick={onDelete}>
      Delete
    </Button>
  </div>

  {#if server.status === 'running'}
    <div class="mt-4 space-y-2">
      <div class="flex items-center gap-2">
        <span class="text-sm text-muted-foreground">IP:</span>
        <code class="text-sm bg-muted px-2 py-0.5 rounded">{server.public_net.ipv4.ip}</code>
        <button
          class="text-muted-foreground hover:text-foreground"
          onclick={() => copyToClipboard(server.public_net.ipv4.ip, 'IP')}
          aria-label="Copy IP"
        >
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        </button>
      </div>

      {#if accessToken}
        <div class="flex flex-wrap gap-2">
          <a
            href="{baseUrl}/?tkn={accessToken}"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-primary hover:underline"
          >
            Overview
          </a>
          <a
            href="{baseUrl}/terminal/?tkn={accessToken}"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-primary hover:underline"
          >
            Terminal
          </a>
          <a
            href="{baseUrl}/code/?tkn={accessToken}"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-primary hover:underline"
          >
            VS Code
          </a>
        </div>
      {/if}
    </div>
  {/if}
</Card>
