<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title?: string;
    description?: string;
    class?: string;
    children: Snippet;
    footer?: Snippet;
  }

  let { title, description, class: className = '', children, footer }: Props = $props();
</script>

<div class="bg-card border border-border rounded-lg {className}">
  {#if title || description}
    <div class="px-6 py-4 border-b border-border">
      {#if title}
        <h2 class="text-lg font-semibold">{title}</h2>
      {/if}
      {#if description}
        <p class="text-sm text-muted-foreground mt-1">{description}</p>
      {/if}
    </div>
  {/if}

  <div class="px-6 py-4">
    {@render children()}
  </div>

  {#if footer}
    <div class="px-6 py-4 border-t border-border">
      {@render footer()}
    </div>
  {/if}
</div>
