import { describe, expect, it } from 'vitest';

import { generateSSHHostKey, isValidSSHHostKey } from '$lib/utils/ssh-keygen';

describe('generateSSHHostKey', () => {
  it('generates a key pair with private and public keys', () => {
    const key = generateSSHHostKey();
    expect(key.privateKey).toBeTruthy();
    expect(key.publicKey).toBeTruthy();
  });

  it('generates private key in OpenSSH format', () => {
    const key = generateSSHHostKey();
    expect(key.privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(key.privateKey).toContain('-----END OPENSSH PRIVATE KEY-----');
  });

  it('generates public key in ssh-ed25519 format', () => {
    const key = generateSSHHostKey();
    expect(key.publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ devbox-host-key$/);
  });

  it('generates unique keys on each call', () => {
    const key1 = generateSSHHostKey();
    const key2 = generateSSHHostKey();
    expect(key1.privateKey).not.toBe(key2.privateKey);
    expect(key1.publicKey).not.toBe(key2.publicKey);
  });

  it('private key contains base64-encoded data between headers', () => {
    const key = generateSSHHostKey();
    const lines = key.privateKey.split('\n');
    expect(lines[0]).toBe('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(lines.at(-2)).toBe('-----END OPENSSH PRIVATE KEY-----');
    // Lines between headers should be base64
    const b64Lines = lines.slice(1, -2);
    for (const line of b64Lines) {
      expect(line).toMatch(/^[A-Za-z0-9+/=]+$/);
    }
  });

  it('private key lines are at most 70 characters', () => {
    const key = generateSSHHostKey();
    const lines = key.privateKey.split('\n');
    const b64Lines = lines.slice(1, -2);
    for (const line of b64Lines) {
      expect(line.length).toBeLessThanOrEqual(70);
    }
  });
});

describe('isValidSSHHostKey', () => {
  it('returns true for a valid generated key', () => {
    const key = generateSSHHostKey();
    expect(isValidSSHHostKey(key)).toBe(true);
  });

  it('returns false for empty keys', () => {
    expect(isValidSSHHostKey({ privateKey: '', publicKey: '' })).toBe(false);
  });

  it('returns false when private key is missing header', () => {
    const key = generateSSHHostKey();
    expect(isValidSSHHostKey({ privateKey: 'not-a-key', publicKey: key.publicKey })).toBe(false);
  });

  it('returns false when public key has wrong prefix', () => {
    const key = generateSSHHostKey();
    expect(isValidSSHHostKey({ privateKey: key.privateKey, publicKey: 'ssh-rsa AAAA foo' })).toBe(false);
  });

  it('returns false for corrupted private key', () => {
    expect(
      isValidSSHHostKey({
        privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid-base64!\n-----END OPENSSH PRIVATE KEY-----\n',
        publicKey: 'ssh-ed25519 AAAA test',
      }),
    ).toBe(false);
  });

  it('returns false when private key has wrong magic bytes', () => {
    // Valid base64 but wrong content
    const fakeContent = btoa('not-openssh-key-v1\0' + 'x'.repeat(100));
    expect(
      isValidSSHHostKey({
        privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${fakeContent}\n-----END OPENSSH PRIVATE KEY-----\n`,
        publicKey: 'ssh-ed25519 AAAA test',
      }),
    ).toBe(false);
  });
});
