<script lang="ts">
  import type { Snippet } from 'svelte';

  import { fade, scale } from 'svelte/transition';

  interface Props {
    actions?: Snippet;
    children: Snippet;
    maxWidth?: string;
    onClose: () => void;
    open: boolean;
    title: string;
  }

  // eslint-disable-next-line @typescript-eslint/no-useless-default-assignment -- $bindable() is Svelte 5 syntax, not a default value
  let { actions, children, maxWidth = 'max-w-md', onClose, open = $bindable(), title }: Props = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      onClose();
    }
  }

  function handleBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) {
      onClose();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

{#if open}
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
    role="dialog"
    aria-modal="true"
    aria-labelledby="modal-title"
    tabindex="-1"
    onclick={handleBackdropClick}
    onkeydown={(e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    }}
    transition:fade={{ duration: 150 }}
  >
    <div
      class="bg-card border-border w-full rounded-lg border-2 shadow-xl {maxWidth}"
      transition:scale={{ duration: 150, start: 0.95 }}
    >
      <div class="border-border border-b px-6 py-4">
        <h2 id="modal-title" class="text-lg font-semibold">{title}</h2>
      </div>

      <div class="px-6 py-4">
        {@render children()}
      </div>

      {#if actions}
        <div class="border-border flex justify-end gap-3 border-t px-6 py-4">
          {@render actions()}
        </div>
      {/if}
    </div>
  </div>
{/if}
