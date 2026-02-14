<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    children: Snippet;
    class?: string;
    description?: string;
    footer?: Snippet;
    title?: string;
  }

  let { children, class: className = '', description, footer, title }: Props = $props();
</script>

<div class="bg-card border-border rounded-lg border {className}">
  {#if title ?? description}
    <div class="border-border border-b px-6 py-4">
      {#if title}
        <h2 class="text-lg font-semibold">{title}</h2>
      {/if}
      {#if description}
        <p class="text-muted-foreground mt-1 text-sm">{description}</p>
      {/if}
    </div>
  {/if}

  <div class="px-6 py-4">
    {@render children()}
  </div>

  {#if footer}
    <div class="border-border border-t px-6 py-4">
      {@render footer()}
    </div>
  {/if}
</div>
