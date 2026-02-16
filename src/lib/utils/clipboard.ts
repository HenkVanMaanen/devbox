import { toast } from '$lib/stores/toast.svelte';

export async function copyToClipboard(text: string, label: string): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      // Fallback for HTTP contexts where navigator.clipboard is unavailable
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.append(textarea);
      textarea.select();
      // eslint-disable-next-line @typescript-eslint/no-deprecated
      document.execCommand('copy');
      textarea.remove();
    }
    toast.success(`${label} copied`);
  } catch {
    toast.error('Failed to copy');
  }
}
