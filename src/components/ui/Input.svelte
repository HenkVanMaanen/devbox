<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  import { uuid } from '$lib/utils/storage';

  interface Props extends Omit<HTMLInputAttributes, 'class'> {
    class?: string;
    error?: string;
    help?: string;
    label?: string;
  }

  let { class: className = '', error, help, id, label, value = $bindable(''), ...rest }: Props = $props();

  // Generate a stable ID for the input
  const generatedId = uuid();
  const inputId = $derived(id ?? generatedId);
</script>

<div class="field">
  {#if label}
    <label for={inputId} class="mb-1.5 block text-sm font-medium">{label}</label>
  {/if}

  <input
    {id}
    bind:value
    class="bg-background focus:ring-focus focus:ring-offset-background focus:border-primary placeholder:text-placeholder min-h-[44px] w-full rounded-md
           border-2 px-3 py-2 text-base focus:ring-3 focus:ring-offset-2
           focus:outline-none
           {error ? 'border-destructive' : 'border-border'}
           {className}"
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={help || error ? `${inputId}-description` : undefined}
    {...rest}
  />

  {#if help && !error}
    <p id="{inputId}-description" class="text-muted-foreground mt-1 text-sm">{help}</p>
  {/if}

  {#if error}
    <p id="{inputId}-description" class="text-destructive mt-1 text-sm">{error}</p>
  {/if}
</div>
