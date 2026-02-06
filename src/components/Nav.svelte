<script lang="ts">
  import ThemeSelector from './ThemeSelector.svelte';
  import changelog from '../../CHANGELOG.md?raw';
  import Modal from './ui/Modal.svelte';
  import Button from './ui/Button.svelte';

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

<nav class="border-b-2 border-border bg-card sticky top-0 z-40">
  <div class="max-w-4xl mx-auto px-4 h-16 flex items-center justify-between">
    <span class="text-xl font-bold">Devbox</span>

    <div class="flex items-center gap-1">
      <div class="flex gap-1" role="menubar">
        {#each navItems as item}
          <a
            href="#{item.id}"
            class="nav-link min-h-[44px] min-w-[44px] px-4 py-2 rounded-md text-base font-medium transition-colors flex items-center
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
        onclick={() => showChangelog = true}
        class="text-xs text-muted-foreground ml-2 opacity-60 hover:opacity-100 focus:opacity-100 focus:outline-none focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background rounded transition-opacity cursor-pointer"
        aria-label="View changelog for version {version}"
        title="View changelog"
      >
        v{version}
      </button>
    </div>
  </div>
</nav>

<Modal
  bind:open={showChangelog}
  title="Changelog"
  onClose={() => showChangelog = false}
  maxWidth="max-w-2xl"
>
  <div class="max-h-[60vh] overflow-y-auto text-sm">
    <pre class="whitespace-pre-wrap font-sans leading-relaxed">{changelog}</pre>
  </div>
  {#snippet actions()}
    <Button variant="secondary" onclick={() => showChangelog = false}>
      Close
    </Button>
  {/snippet}
</Modal>
