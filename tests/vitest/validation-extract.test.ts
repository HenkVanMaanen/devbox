import { describe, expect, it } from 'vitest';

import { extractSSHKeyName } from '$lib/utils/validation';

describe('extractSSHKeyName', () => {
  it('extracts comment from standard SSH key', () => {
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@laptop');
    expect(result).toBe('user@laptop');
  });

  it('extracts multi-word comment', () => {
    const result = extractSSHKeyName('ssh-rsa AAAAB3NzaC1yc2EAAAA my work key');
    expect(result).toBe('my work key');
  });

  it('returns null for key with no comment', () => {
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest');
    expect(result).toBeNull();
  });

  it('returns null for comment longer than 100 chars', () => {
    const longComment = 'a'.repeat(101);
    const result = extractSSHKeyName(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ${longComment}`);
    expect(result).toBeNull();
  });

  it('returns comment with exactly 100 characters', () => {
    const comment = 'a'.repeat(100);
    const result = extractSSHKeyName(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ${comment}`);
    expect(result).toBe(comment);
  });

  it('returns null for empty string input', () => {
    expect(extractSSHKeyName('')).toBeNull();
  });

  it('returns null for non-string input', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(extractSSHKeyName(null as any)).toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(extractSSHKeyName(undefined as any)).toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(extractSSHKeyName(42 as any)).toBeNull();
  });

  it('handles leading/trailing whitespace in key', () => {
    const result = extractSSHKeyName('  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@laptop  ');
    expect(result).toBe('user@laptop');
  });

  it('returns null for single-word input', () => {
    expect(extractSSHKeyName('ssh-ed25519')).toBeNull();
  });

  it('handles tab-separated comment', () => {
    const result = extractSSHKeyName('ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAA\tuser@laptop');
    expect(result).toBe('user@laptop');
  });

  it('trims trailing whitespace from comment (kills .trim() removal on slice().join())', () => {
    // If .trim() was removed from parts.slice(2).join(' ').trim(), trailing space would remain
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@laptop   ');
    expect(result).toBe('user@laptop');
    // Ensure no trailing spaces
    expect(result).not.toMatch(/\s$/);
  });

  it('split uses \\s+ to collapse multiple spaces (kills \\s+ → \\s)', () => {
    // With \s, multiple spaces between parts would create empty string elements in the array
    // With \s+, they are treated as a single delimiter
    const result = extractSSHKeyName('ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAItest   user@laptop');
    expect(result).toBe('user@laptop');
    // Must not start or end with space
    expect(result).not.toMatch(/^\s/);
    expect(result).not.toMatch(/\s$/);
  });

  it('returns null for falsy pubKey (kills !pubKey guard)', () => {
    // If !pubKey was mutated to always false, it would try to call .trim() on falsy value
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(extractSSHKeyName('' as any)).toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(extractSSHKeyName(0 as any)).toBeNull();
  });

  it('comment with only whitespace returns null after trim', () => {
    // parts.slice(2).join(' ').trim() would be empty, so length > 0 check fails
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest    ');
    expect(result).toBeNull();
  });
});
