import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('toast store', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function getStore() {
    const { toast } = await import('$lib/stores/toast.svelte');
    return toast;
  }

  it('adds info toast with correct type and message', async () => {
    const store = await getStore();
    store.info('hello');
    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.type).toBe('info');
    expect(store.toasts[0]?.message).toBe('hello');
  });

  it('adds error toast with correct type and message', async () => {
    const store = await getStore();
    store.error('something went wrong');
    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.type).toBe('error');
    expect(store.toasts[0]?.message).toBe('something went wrong');
  });

  it('adds success toast with correct type and message', async () => {
    const store = await getStore();
    store.success('done');
    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.type).toBe('success');
    expect(store.toasts[0]?.message).toBe('done');
  });

  it('error toast defaults to 5000ms duration', async () => {
    const store = await getStore();
    store.error('fail');
    expect(store.toasts).toHaveLength(1);

    // Should still exist at 4999ms
    vi.advanceTimersByTime(4999);
    expect(store.toasts).toHaveLength(1);

    // Should be removed at 5000ms
    vi.advanceTimersByTime(1);
    expect(store.toasts).toHaveLength(0);
  });

  it('info toast defaults to 3000ms duration', async () => {
    const store = await getStore();
    store.info('notice');
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(2999);
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(1);
    expect(store.toasts).toHaveLength(0);
  });

  it('success toast defaults to 3000ms duration', async () => {
    const store = await getStore();
    store.success('yay');
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(2999);
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(1);
    expect(store.toasts).toHaveLength(0);
  });

  it('removes toast by id', async () => {
    const store = await getStore();
    store.info('first');
    store.info('second');
    expect(store.toasts).toHaveLength(2);

    const idToRemove = store.toasts[0]?.id;
    expect(idToRemove).toBeDefined();
    store.remove(idToRemove!);

    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.message).toBe('second');
  });

  it('removing non-existent id does nothing', async () => {
    const store = await getStore();
    store.info('only one');
    expect(store.toasts).toHaveLength(1);

    store.remove('non-existent-id');
    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.message).toBe('only one');
  });

  it('auto-removes toast after timeout', async () => {
    const store = await getStore();
    store.info('will vanish');
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(3000);
    expect(store.toasts).toHaveLength(0);
  });

  it('multiple toasts accumulate', async () => {
    const store = await getStore();
    store.info('first');
    store.error('second');
    store.success('third');
    expect(store.toasts).toHaveLength(3);
    expect(store.toasts[0]?.message).toBe('first');
    expect(store.toasts[1]?.message).toBe('second');
    expect(store.toasts[2]?.message).toBe('third');
  });

  it('toasts getter returns current list', async () => {
    const store = await getStore();
    expect(store.toasts).toEqual([]);

    store.info('a');
    const list = store.toasts;
    expect(list).toHaveLength(1);
    expect(list[0]?.message).toBe('a');
  });

  it('each toast gets a unique id', async () => {
    const store = await getStore();
    store.info('a');
    store.info('b');
    expect(store.toasts[0]?.id).not.toBe(store.toasts[1]?.id);
  });

  it('respects custom duration on error toast', async () => {
    const store = await getStore();
    store.error('short error', 1000);
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(999);
    expect(store.toasts).toHaveLength(1);

    vi.advanceTimersByTime(1);
    expect(store.toasts).toHaveLength(0);
  });

  it('multiple toasts auto-remove independently', async () => {
    const store = await getStore();
    store.info('fast', 1000);
    store.info('slow', 5000);
    expect(store.toasts).toHaveLength(2);

    vi.advanceTimersByTime(1000);
    expect(store.toasts).toHaveLength(1);
    expect(store.toasts[0]?.message).toBe('slow');

    vi.advanceTimersByTime(4000);
    expect(store.toasts).toHaveLength(0);
  });
});
