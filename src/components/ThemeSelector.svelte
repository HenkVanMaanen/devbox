<script lang="ts">
  import { themeStore } from '$lib/stores/theme.svelte';

  let isOpen = $state(false);

  function selectTheme(themeId: string) {
    themeStore.setTheme(themeId);
    isOpen = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      isOpen = false;
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="relative">
  <button
    onclick={() => (isOpen = !isOpen)}
    class="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground rounded-md hover:bg-muted transition-colors"
    aria-expanded={isOpen}
    aria-haspopup="true"
  >
    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"
      />
    </svg>
    <span class="hidden sm:inline">{themeStore.theme.name}</span>
  </button>

  {#if isOpen}
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="fixed inset-0 z-40"
      onclick={() => (isOpen = false)}
      onkeydown={(e) => e.key === 'Escape' && (isOpen = false)}
    ></div>
    <div
      class="absolute right-0 top-full mt-2 w-48 bg-card border-2 border-border rounded-lg shadow-xl z-50 py-1 max-h-80 overflow-y-auto"
      role="menu"
    >
      {#each themeStore.themes as theme}
        <button
          onclick={() => selectTheme(theme.id)}
          class="w-full px-4 py-2 text-left text-sm hover:bg-muted flex items-center gap-2 {theme.id ===
          themeStore.themeId
            ? 'text-primary font-medium'
            : 'text-foreground'}"
          role="menuitem"
        >
          <span
            class="w-4 h-4 rounded-full border border-border"
            style="background: {theme.colors.background}"
          ></span>
          {theme.name}
          {#if theme.id === themeStore.themeId}
            <svg class="w-4 h-4 ml-auto" fill="currentColor" viewBox="0 0 20 20">
              <path
                fill-rule="evenodd"
                d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                clip-rule="evenodd"
              />
            </svg>
          {/if}
        </button>
      {/each}
    </div>
  {/if}
</div>
