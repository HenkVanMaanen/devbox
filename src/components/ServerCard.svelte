<script lang="ts">
  import type { Server } from '$lib/types';
  import { serversStore } from '$lib/stores/servers.svelte';
  import { configStore } from '$lib/stores/config.svelte';
  import { generateQR } from '$lib/utils/qrcode';
  import Button from './ui/Button.svelte';
  import Card from './ui/Card.svelte';
  import { toast } from '$lib/stores/toast.svelte';

  interface Props {
    server: Server;
    onDelete: () => void;
  }

  let { server, onDelete }: Props = $props();

  function ipToHex(ip: string): string {
    return ip.split('.').map(o => parseInt(o, 10).toString(16).padStart(2, '0')).join('');
  }

  const accessToken = $derived(serversStore.getServerToken(server.name));
  // Use custom domain if configured, otherwise use the selected DNS service
  const dnsService = $derived(
    configStore.value.services.dnsService === 'custom'
      ? (configStore.value.services.customDnsDomain || 'sslip.io')
      : (configStore.value.services.dnsService || 'sslip.io')
  );
  const ipHex = $derived(ipToHex(server.public_net.ipv4.ip));
  const baseUrl = $derived(`https://${ipHex}.${dnsService}`);

  // Generate QR code for easy mobile access
  const qrCodeSvg = $derived.by(() => {
    if (!accessToken || server.status !== 'running') return '';
    try {
      const url = `https://devbox:${encodeURIComponent(accessToken)}@${ipHex}.${dnsService}/`;
      return generateQR(url);
    } catch {
      return '';
    }
  });

  // Progress tracking
  const progress = $derived(server.labels['progress'] ?? '');
  const isProvisioning = $derived(progress !== '' && progress !== 'ready');

  const provisioningSteps = ['Starting', 'Installing', 'Configuring', 'Ready'];
  const currentStep = $derived.by(() => {
    if (progress === 'ready') return 3;
    if (progress === 'configuring') return 2;
    if (server.status === 'running') return 1;
    return 0;
  });

  const statusColors: Record<string, string> = {
    running: 'bg-success/30 text-success',
    starting: 'bg-warning/30 text-warning',
    stopping: 'bg-warning/30 text-warning',
    off: 'bg-muted text-muted-foreground',
    initializing: 'bg-primary/30 text-primary',
  };

  // Badge: "not ready" / "ready" during provisioning, otherwise server status
  const badgeLabel = $derived(
    progress === '' ? server.status : isProvisioning ? 'not ready' : 'ready'
  );
  const badgeColor = $derived(
    progress === '' ? (statusColors[server.status] ?? statusColors['off'])
    : isProvisioning ? 'bg-warning/30 text-warning'
    : 'bg-success/30 text-success'
  );

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
        <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold {badgeColor}">
          {badgeLabel}
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

  {#if isProvisioning}
    <div class="mt-3" role="group" aria-label="Server provisioning steps">
      <div class="flex items-center">
        {#each provisioningSteps as _, i}
          {#if i > 0}
            <div class="flex-1 h-0.5 transition-colors duration-500 {i <= currentStep ? 'bg-primary' : 'bg-muted'}"></div>
          {/if}
          <div
            class="w-2.5 h-2.5 rounded-full flex-shrink-0 transition-colors duration-500
              {i < currentStep ? 'bg-primary' : i === currentStep ? 'bg-primary animate-pulse' : 'bg-muted'}"
          ></div>
        {/each}
      </div>
      <div class="flex justify-between mt-1.5">
        {#each provisioningSteps as step, i}
          <span class="text-[10px] leading-tight {i === currentStep ? 'text-foreground font-medium' : i < currentStep ? 'text-muted-foreground' : 'text-muted-foreground/50'}">{step}</span>
        {/each}
      </div>
    </div>
  {/if}

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
        {@const overviewUrl = `${baseUrl}/`}
        {@const terminalUrl = `https://65534.${ipHex}.${dnsService}/`}

        <div class="space-y-2">
          <div class="flex items-center gap-2">
            <a
              href="https://devbox:{accessToken}@{ipHex}.{dnsService}/"
              target="_blank"
              rel="noopener noreferrer"
              class="text-sm text-primary hover:underline"
            >
              Overview
            </a>
            <button
              class="text-muted-foreground hover:text-foreground"
              onclick={() => copyToClipboard(overviewUrl, 'Overview URL')}
              aria-label="Copy Overview URL"
            >
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
            </button>
          </div>

          <div class="flex items-center gap-2">
            <a
              href="https://devbox:{accessToken}@65534.{ipHex}.{dnsService}/"
              target="_blank"
              rel="noopener noreferrer"
              class="text-sm text-primary hover:underline"
            >
              Terminal
            </a>
            <button
              class="text-muted-foreground hover:text-foreground"
              onclick={() => copyToClipboard(terminalUrl, 'Terminal URL')}
              aria-label="Copy Terminal URL"
            >
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
            </button>
          </div>

          {#if qrCodeSvg}
            <div class="mt-3 pt-3 border-t border-border">
              <p class="text-xs text-muted-foreground mb-2">Scan to access on mobile</p>
              <div class="flex justify-center">
                <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                <div class="bg-white p-2 rounded-md" style="width: 144px; height: 144px;">{@html qrCodeSvg}</div>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</Card>
