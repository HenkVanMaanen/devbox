<script lang="ts">
  import YAML from 'yaml';

  import type { CustomCloudInitConfig } from '$lib/types';

  import { BLOCKED_CUSTOM_KEYS } from '$lib/utils/cloudinit';

  interface Props {
    getValue: (path: string) => unknown;
    idPrefix?: string;
    isDisabled?: (path: string) => boolean;
    setValue: (path: string, value: unknown) => void;
  }

  let { getValue, idPrefix = '', isDisabled, setValue }: Props = $props();

  // Read whole object to work with profile overrides as a single unit
  const config = $derived(getValue('customCloudInit') as CustomCloudInitConfig);

  // YAML validation
  const validationError = $derived.by(() => {
    const yaml = config.yaml.trim();
    if (!yaml) return '';
    try {
      YAML.parse(yaml);
      return '';
    } catch (error) {
      return error instanceof Error ? error.message : 'Invalid YAML';
    }
  });

  // Merge mode info: summarize which sections user YAML contributes
  const mergeInfo = $derived.by(() => {
    const yaml = config.yaml.trim();
    if (!yaml || config.mode !== 'merge' || validationError) return '';
    try {
      const parsed = YAML.parse(yaml);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return '';
      const keys = Object.keys(parsed);
      if (keys.length === 0) return '';
      const active = keys.filter((k) => !BLOCKED_CUSTOM_KEYS.has(k));
      const ignored = keys.filter((k) => BLOCKED_CUSTOM_KEYS.has(k));
      const parts: string[] = [];
      if (active.length > 0) parts.push(`Sections to merge: ${active.join(', ')}`);
      if (ignored.length > 0) parts.push(`Ignored (managed by devbox): ${ignored.join(', ')}`);
      return parts.join('. ');
    } catch {
      return '';
    }
  });

  const disabled = $derived(isDisabled ? isDisabled('customCloudInit') : false);

  function onYamlChange(e: Event) {
    const textarea = e.currentTarget as HTMLTextAreaElement;
    setValue('customCloudInit', { ...config, yaml: textarea.value });
  }

  function onModeChange(e: Event) {
    const select = e.currentTarget as HTMLSelectElement;
    setValue('customCloudInit', { ...config, mode: select.value as 'merge' | 'replace' });
  }
</script>

<div class="space-y-4">
  <div>
    <label for="{idPrefix}custom-cloudinit-mode" class="mb-1.5 block text-sm font-medium">Mode</label>
    <select
      id="{idPrefix}custom-cloudinit-mode"
      value={config.mode}
      onchange={onModeChange}
      {disabled}
      class="bg-background border-border focus:ring-focus focus:border-primary min-h-[44px] w-full rounded-md border-2 px-3
             py-2 text-base focus:ring-3 focus:outline-none
             disabled:cursor-not-allowed disabled:opacity-50"
    >
      <option value="merge">Merge with generated</option>
      <option value="replace">Replace generated</option>
    </select>
  </div>

  {#if config.mode === 'replace'}
    <div class="bg-warning/10 border-warning/30 rounded-md border p-3">
      <p class="text-warning text-sm font-medium">
        Devbox features (auto-delete, progress tracking, web terminal, dashboard) will not be available when using
        replace mode.
      </p>
    </div>
  {/if}

  <div>
    <label for="{idPrefix}custom-cloudinit-yaml" class="mb-1.5 block text-sm font-medium">Custom Cloud-Init YAML</label>
    <textarea
      id="{idPrefix}custom-cloudinit-yaml"
      value={config.yaml}
      onchange={onYamlChange}
      {disabled}
      placeholder="packages:&#10;  - python3&#10;  - golang&#10;&#10;runcmd:&#10;  - echo 'Hello from custom cloud-init'"
      class="bg-background focus:ring-focus focus:border-primary placeholder:text-placeholder min-h-[200px] w-full resize-y rounded-md
             border-2 px-3 py-2 font-mono
             text-base text-sm
             focus:ring-3 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50
             {validationError ? 'border-destructive' : 'border-border'}"
    ></textarea>
    {#if validationError}
      <p class="text-destructive mt-1 text-sm">{validationError}</p>
    {/if}
    {#if mergeInfo}
      <p class="text-muted-foreground mt-1 text-sm">{mergeInfo}</p>
    {/if}
  </div>
</div>
