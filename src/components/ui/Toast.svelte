<script lang="ts">
  import { toast } from '$lib/stores/toast.svelte';
  import { fly } from 'svelte/transition';

  const typeClasses = {
    success: 'bg-success/20 text-success border-success/50',
    error: 'bg-destructive/20 text-destructive border-destructive/50',
    info: 'bg-primary/20 text-primary border-primary/50',
  };
</script>

<div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2" role="status" aria-live="polite">
  {#each toast.toasts as t (t.id)}
    <div
      class="px-4 py-3 rounded-lg border-2 shadow-lg max-w-sm {typeClasses[t.type]}"
      transition:fly={{ x: 100, duration: 200 }}
    >
      <div class="flex items-center justify-between gap-3">
        <p class="text-sm font-medium">{t.message}</p>
        <button
          class="text-current opacity-70 hover:opacity-100"
          onclick={() => toast.remove(t.id)}
          aria-label="Dismiss"
        >
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  {/each}
</div>
