<script lang="ts">
  import type { Snippet } from 'svelte';
  import { fade, scale } from 'svelte/transition';

  interface Props {
    open: boolean;
    title: string;
    onClose: () => void;
    children: Snippet;
    actions?: Snippet;
  }

  let { open = $bindable(), title, onClose, children, actions }: Props = $props();

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
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
    role="dialog"
    aria-modal="true"
    aria-labelledby="modal-title"
    tabindex="-1"
    onclick={handleBackdropClick}
    onkeydown={(e) => e.key === 'Escape' && onClose()}
    transition:fade={{ duration: 150 }}
  >
    <div
      class="bg-card border-2 border-border rounded-lg shadow-xl w-full max-w-md"
      transition:scale={{ start: 0.95, duration: 150 }}
    >
      <div class="px-6 py-4 border-b border-border">
        <h2 id="modal-title" class="text-lg font-semibold">{title}</h2>
      </div>

      <div class="px-6 py-4">
        {@render children()}
      </div>

      {#if actions}
        <div class="px-6 py-4 border-t border-border flex justify-end gap-3">
          {@render actions()}
        </div>
      {/if}
    </div>
  </div>
{/if}
