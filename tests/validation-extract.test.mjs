import { describe, it } from 'node:test';
import assert from 'node:assert';

import { extractSSHKeyName } from '../src/lib/utils/validation.ts';

describe('extractSSHKeyName', () => {
  it('extracts comment from standard SSH key', () => {
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@laptop');
    assert.strictEqual(result, 'user@laptop');
  });

  it('extracts multi-word comment', () => {
    const result = extractSSHKeyName('ssh-rsa AAAAB3NzaC1yc2EAAAA my work key');
    assert.strictEqual(result, 'my work key');
  });

  it('returns null for key with no comment', () => {
    const result = extractSSHKeyName('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest');
    assert.strictEqual(result, null);
  });

  it('returns null for comment longer than 100 chars', () => {
    const longComment = 'a'.repeat(101);
    const result = extractSSHKeyName(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ${longComment}`);
    assert.strictEqual(result, null);
  });

  it('returns comment with exactly 100 characters', () => {
    const comment = 'a'.repeat(100);
    const result = extractSSHKeyName(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ${comment}`);
    assert.strictEqual(result, comment);
  });

  it('returns null for empty string input', () => {
    assert.strictEqual(extractSSHKeyName(''), null);
  });

  it('returns null for non-string input', () => {
    assert.strictEqual(extractSSHKeyName(null), null);
    assert.strictEqual(extractSSHKeyName(undefined), null);
    assert.strictEqual(extractSSHKeyName(42), null);
  });

  it('handles leading/trailing whitespace in key', () => {
    const result = extractSSHKeyName('  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@laptop  ');
    assert.strictEqual(result, 'user@laptop');
  });

  it('returns null for single-word input', () => {
    assert.strictEqual(extractSSHKeyName('ssh-ed25519'), null);
  });

  it('handles tab-separated comment', () => {
    const result = extractSSHKeyName('ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAA\tuser@laptop');
    assert.strictEqual(result, 'user@laptop');
  });
});
