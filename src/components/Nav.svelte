<script lang="ts">
  import changelogHtml from '../../CHANGELOG.md?html';
  import ThemeSelector from './ThemeSelector.svelte';
  import Button from './ui/Button.svelte';
  import Modal from './ui/Modal.svelte';

  interface Props {
    currentPage: string;
  }

  let { currentPage }: Props = $props();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'config', label: 'Global' },
    { id: 'profiles', label: 'Profiles' },
    { id: 'cloudinit', label: 'Cloud-Init' },
    { id: 'credentials', label: 'API Token' },
  ];

  const version = __APP_VERSION__;
  let showChangelog = $state(false);
</script>

<nav class="border-border bg-card sticky top-0 z-40 border-b-2">
  <div class="mx-auto flex h-16 max-w-4xl items-center justify-between px-4">
    <span class="text-xl font-bold">Devbox</span>

    <div class="flex items-center gap-1">
      <div class="flex gap-1" role="menubar">
        {#each navItems as item (item.id)}
          <a
            href="#{item.id}"
            class="nav-link flex min-h-[44px] min-w-[44px] items-center rounded-md px-4 py-2 text-base font-medium transition-colors
                   {currentPage === item.id
              ? 'text-foreground bg-muted'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted'}"
            role="menuitem"
            aria-current={currentPage === item.id ? 'page' : undefined}
          >
            {item.label}
          </a>
        {/each}
      </div>

      <ThemeSelector />
      <button
        type="button"
        onclick={() => (showChangelog = true)}
        class="text-muted-foreground focus:ring-focus focus:ring-offset-background ml-2 cursor-pointer rounded text-xs opacity-60 transition-opacity hover:opacity-100 focus:opacity-100 focus:ring-3 focus:ring-offset-2 focus:outline-none"
        aria-label="View changelog for version {version}"
        title="View changelog"
      >
        v{version}
      </button>
    </div>
  </div>
</nav>

<Modal bind:open={showChangelog} title="Changelog" onClose={() => (showChangelog = false)} maxWidth="max-w-2xl">
  <div class="changelog max-h-[60vh] overflow-y-auto text-sm">
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html changelogHtml}
  </div>
  {#snippet actions()}
    <Button variant="secondary" onclick={() => (showChangelog = false)}>Close</Button>
  {/snippet}
</Modal>

<style>
  @reference '../app.css';

  .changelog :global(h1) {
    @apply mb-4 text-xl font-bold;
  }
  .changelog :global(h2) {
    @apply border-border mt-6 mb-3 border-b pb-1 text-lg font-semibold;
  }
  .changelog :global(h3) {
    @apply text-muted-foreground mt-4 mb-2 text-base font-medium;
  }
  .changelog :global(ul) {
    @apply my-2 list-disc pl-5;
  }
  .changelog :global(li) {
    @apply my-1;
  }
  .changelog :global(a) {
    @apply text-primary hover:underline;
  }
  .changelog :global(p) {
    @apply my-2;
  }
</style>
