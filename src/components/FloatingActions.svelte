<script lang="ts">
  import { fly } from 'svelte/transition';
  import Button from './ui/Button.svelte';

  interface Props {
    onSave: () => void;
    onDiscard: () => void;
    saving?: boolean;
  }

  let { onSave, onDiscard, saving = false }: Props = $props();
</script>

<div
  class="fixed bottom-0 left-0 right-0 z-40 flex items-center justify-center gap-4 px-6 py-4
         bg-card border-t-2 border-border shadow-[0_-4px_20px_rgba(0,0,0,0.3)]"
  transition:fly={{ y: 100, duration: 200 }}
>
  <span class="text-sm text-muted-foreground">You have unsaved changes</span>
  <Button variant="secondary" onclick={onDiscard}>Discard</Button>
  <Button variant="primary" onclick={onSave} loading={saving}>Save Changes</Button>
</div>
