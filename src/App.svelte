<script lang="ts">
  import Nav from '$components/Nav.svelte';
  import Toast from '$components/ui/Toast.svelte';
  import Dashboard from '$pages/Dashboard.svelte';
  import Config from '$pages/Config.svelte';
  import Profiles from '$pages/Profiles.svelte';
  import ProfileEdit from '$pages/ProfileEdit.svelte';
  import Credentials from '$pages/Credentials.svelte';
  import CloudInit from '$pages/CloudInit.svelte';

  // Simple hash-based routing with params
  let hash = $state(window.location.hash.slice(1) || 'dashboard');
  let currentPage = $derived(hash.split('/')[0] || 'dashboard');
  let pageParam = $derived(hash.split('/')[1] || '');

  $effect(() => {
    function handleHashChange() {
      hash = window.location.hash.slice(1) || 'dashboard';
    }

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  });
</script>

<div class="min-h-screen bg-background text-foreground">
  <Nav {currentPage} />

  <main class="max-w-4xl mx-auto px-4 py-6">
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
