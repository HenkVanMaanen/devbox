<script lang="ts">
  interface Props {
    currentPage: string;
  }

  let { currentPage }: Props = $props();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'config', label: 'Global' },
    { id: 'profiles', label: 'Profiles' },
    { id: 'credentials', label: 'API Token' },
  ];

  const version = __APP_VERSION__;
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

      <span class="text-xs text-muted-foreground ml-2 opacity-60">v{version}</span>
    </div>
  </div>
</nav>
