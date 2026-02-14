<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';

  interface Props extends HTMLButtonAttributes {
    children: Snippet;
    loading?: boolean;
    size?: 'default' | 'sm';
    variant?: 'destructive' | 'ghost' | 'primary' | 'secondary';
  }

  let {
    children,
    class: className = '',
    disabled,
    loading = false,
    size = 'default',
    variant = 'primary',
    ...rest
  }: Props = $props();

  const baseClasses =
    'inline-flex items-center justify-center font-medium rounded-md transition-colors focus:outline-none focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background disabled:opacity-60 disabled:cursor-not-allowed';

  const variantClasses = {
    destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive-hover',
    ghost: 'hover:bg-muted',
    primary: 'bg-primary text-primary-foreground hover:bg-primary-hover',
    secondary: 'bg-muted text-foreground hover:bg-muted-hover',
  };

  const sizeClasses = {
    default: 'min-h-[44px] min-w-[44px] px-4 py-2 text-base',
    sm: 'min-h-[44px] px-3 py-1.5 text-sm',
  };
</script>

<button
  class="{baseClasses} {variantClasses[variant]} {sizeClasses[size]} {className}"
  disabled={disabled ?? loading}
  {...rest}
>
  {#if loading}
    <svg class="mr-2 -ml-1 h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
      <path
        class="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  {/if}
  {@render children()}
</button>
