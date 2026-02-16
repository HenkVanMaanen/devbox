import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('copyToClipboard', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  async function getModule() {
    const { toast } = await import('$lib/stores/toast.svelte');
    const { copyToClipboard } = await import('$lib/utils/clipboard');
    return { copyToClipboard, toast };
  }

  it('uses navigator.clipboard.writeText when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });

    const { copyToClipboard, toast } = await getModule();
    const successSpy = vi.spyOn(toast, 'success');

    await copyToClipboard('test-text', 'Test');

    expect(writeText).toHaveBeenCalledWith('test-text');
    expect(successSpy).toHaveBeenCalledWith('Test copied');
  });

  it('falls back to execCommand when clipboard API is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    const { copyToClipboard, toast } = await getModule();
    const successSpy = vi.spyOn(toast, 'success');

    await copyToClipboard('fallback-text', 'Fallback');

    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(successSpy).toHaveBeenCalledWith('Fallback copied');
  });

  it('shows error toast when clipboard write fails', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'));
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });

    const { copyToClipboard, toast } = await getModule();
    const errorSpy = vi.spyOn(toast, 'error');

    await copyToClipboard('text', 'Label');

    expect(errorSpy).toHaveBeenCalledWith('Failed to copy');
  });
});
