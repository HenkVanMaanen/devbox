<script lang="ts">
  import { fly } from 'svelte/transition';

  import Button from './ui/Button.svelte';

  interface Props {
    onDiscard: () => void;
    onSave: () => void;
    saving?: boolean;
  }

  let { onDiscard, onSave, saving = false }: Props = $props();
</script>

<div
  class="bg-card border-border fixed right-0 bottom-0 left-0 z-40 flex items-center justify-center gap-4
         border-t-2 px-6 py-4 shadow-[0_-4px_20px_rgba(0,0,0,0.3)]"
  transition:fly={{ duration: 200, y: 100 }}
>
  <span class="text-muted-foreground text-sm">You have unsaved changes</span>
  <Button variant="secondary" onclick={onDiscard}>Discard</Button>
  <Button variant="primary" onclick={onSave} loading={saving}>Save Changes</Button>
</div>
