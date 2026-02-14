<script lang="ts">
  import { fly } from 'svelte/transition';

  import { toast } from '$lib/stores/toast.svelte';

  const typeClasses = {
    error: 'bg-destructive/20 text-destructive border-destructive/50',
    info: 'bg-primary/20 text-primary border-primary/50',
    success: 'bg-success/20 text-success border-success/50',
  };
</script>

<div class="fixed right-4 bottom-4 z-50 flex flex-col gap-2" role="status" aria-live="polite">
  {#each toast.toasts as t (t.id)}
    <div
      class="max-w-sm rounded-lg border-2 px-4 py-3 shadow-lg {typeClasses[t.type]}"
      transition:fly={{ duration: 200, x: 100 }}
    >
      <div class="flex items-center justify-between gap-3">
        <p class="text-sm font-medium">{t.message}</p>
        <button
          type="button"
          class="text-current opacity-70 hover:opacity-100"
          onclick={() => {
            toast.remove(t.id);
          }}
          aria-label="Dismiss"
        >
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  {/each}
</div>
