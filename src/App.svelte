<script lang="ts">
  import Nav from '$components/Nav.svelte';
  import Toast from '$components/ui/Toast.svelte';
  import CloudInit from '$pages/CloudInit.svelte';
  import Config from '$pages/Config.svelte';
  import Credentials from '$pages/Credentials.svelte';
  import Dashboard from '$pages/Dashboard.svelte';
  import ProfileEdit from '$pages/ProfileEdit.svelte';
  import Profiles from '$pages/Profiles.svelte';

  // Simple hash-based routing with params
  let hash = $state(window.location.hash.slice(1) || 'dashboard');
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- intentional: empty string should also trigger fallback
  let currentPage = $derived(hash.split('/')[0] || 'dashboard');
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- intentional: empty string should also trigger fallback
  let pageParam = $derived(hash.split('/')[1] || '');

  $effect(() => {
    function handleHashChange() {
      hash = window.location.hash.slice(1) || 'dashboard';
    }

    window.addEventListener('hashchange', handleHashChange);
    return () => {
      window.removeEventListener('hashchange', handleHashChange);
    };
  });
</script>

<div class="bg-background text-foreground min-h-screen">
  <Nav {currentPage} />

  <main class="mx-auto max-w-4xl px-4 py-6">
    {#if currentPage === 'dashboard'}
      <Dashboard />
    {:else if currentPage === 'config'}
      <Config />
    {:else if currentPage === 'profiles' && pageParam}
      <ProfileEdit profileId={pageParam} />
    {:else if currentPage === 'profiles'}
      <Profiles />
    {:else if currentPage === 'credentials'}
      <Credentials />
    {:else if currentPage === 'cloudinit'}
      <CloudInit />
    {:else}
      <Dashboard />
    {/if}
  </main>

  <Toast />
</div>
