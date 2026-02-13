<script lang="ts">
  import type { CustomCloudInitConfig } from '$lib/types';
  import { BLOCKED_CUSTOM_KEYS } from '$lib/utils/cloudinit';
  import YAML from 'yaml';

  interface Props {
    getValue: <T>(path: string) => T;
    setValue: (path: string, value: unknown) => void;
    isDisabled?: (path: string) => boolean;
    idPrefix?: string;
  }

  let { getValue, setValue, isDisabled, idPrefix = '' }: Props = $props();

  // Read whole object to work with profile overrides as a single unit
  const config = $derived(getValue<CustomCloudInitConfig>('customCloudInit'));

  // YAML validation
  const validationError = $derived.by(() => {
    const yaml = config?.yaml?.trim() ?? '';
    if (!yaml) return '';
    try {
      YAML.parse(yaml);
      return '';
    } catch (e) {
      return e instanceof Error ? e.message : 'Invalid YAML';
    }
  });

  // Merge mode info: summarize which sections user YAML contributes
  const mergeInfo = $derived.by(() => {
    const yaml = config?.yaml?.trim() ?? '';
    if (!yaml || config?.mode !== 'merge' || validationError) return '';
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
    <label for="{idPrefix}custom-cloudinit-mode" class="block text-sm font-medium mb-1.5">Mode</label>
    <select
      id="{idPrefix}custom-cloudinit-mode"
      value={config?.mode ?? 'merge'}
      onchange={onModeChange}
      {disabled}
      class="w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md
             focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
             disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <option value="merge">Merge with generated</option>
      <option value="replace">Replace generated</option>
    </select>
  </div>

  {#if config?.mode === 'replace'}
    <div class="p-3 bg-warning/10 border border-warning/30 rounded-md">
      <p class="text-sm text-warning font-medium">Devbox features (auto-delete, progress tracking, web terminal, dashboard) will not be available when using replace mode.</p>
    </div>
  {/if}

  <div>
    <label for="{idPrefix}custom-cloudinit-yaml" class="block text-sm font-medium mb-1.5">Custom Cloud-Init YAML</label>
    <textarea
      id="{idPrefix}custom-cloudinit-yaml"
      value={config?.yaml ?? ''}
      onchange={onYamlChange}
      {disabled}
      placeholder="packages:&#10;  - python3&#10;  - golang&#10;&#10;runcmd:&#10;  - echo 'Hello from custom cloud-init'"
      class="w-full min-h-[200px] px-3 py-2 text-base bg-background border-2 rounded-md
             focus:outline-none focus:ring-3 focus:ring-focus focus:border-primary
             disabled:opacity-50 disabled:cursor-not-allowed
             placeholder:text-placeholder resize-y font-mono text-sm
             {validationError ? 'border-destructive' : 'border-border'}"
    ></textarea>
    {#if validationError}
      <p class="text-sm text-destructive mt-1">{validationError}</p>
    {/if}
    {#if mergeInfo}
      <p class="text-sm text-muted-foreground mt-1">{mergeInfo}</p>
    {/if}
  </div>
</div>
