<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import { uuid } from '$lib/utils/storage';

  interface Props extends Omit<HTMLInputAttributes, 'class'> {
    label?: string;
    help?: string;
    error?: string;
    class?: string;
  }

  let {
    label,
    help,
    error,
    id,
    value = $bindable(''),
    class: className = '',
    ...rest
  }: Props = $props();

  // Generate a stable ID for the input
  const generatedId = uuid();
  const inputId = $derived(id ?? generatedId);
</script>

<div class="field">
  {#if label}
    <label for={inputId} class="block text-sm font-medium mb-1.5">{label}</label>
  {/if}

  <input
    {id}
    bind:value
    class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 rounded-md
           focus:outline-none focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background focus:border-primary
           placeholder:text-placeholder
           {error ? 'border-destructive' : 'border-border'}
           {className}"
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={help || error ? `${inputId}-description` : undefined}
    {...rest}
  />

  {#if help && !error}
    <p id="{inputId}-description" class="text-sm text-muted-foreground mt-1">{help}</p>
  {/if}

  {#if error}
    <p id="{inputId}-description" class="text-sm text-destructive mt-1">{error}</p>
  {/if}
</div>
