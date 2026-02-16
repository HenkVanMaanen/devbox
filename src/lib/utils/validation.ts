// Validation utilities for form fields and SSH keys

import { z } from 'zod';

// Stryker disable all
// SSH key type patterns
const SSH_KEY_PATTERNS: Record<string, RegExp> = {
  'ecdsa-sha2-nistp256': /^ecdsa-sha2-nistp256\s+\S+/,
  'ecdsa-sha2-nistp384': /^ecdsa-sha2-nistp384\s+\S+/,
  'ecdsa-sha2-nistp521': /^ecdsa-sha2-nistp521\s+\S+/,
  'sk-ecdsa-sha2-nistp256@openssh.com': /^sk-ecdsa-sha2-nistp256@openssh\.com\s+\S+/,
  'sk-ssh-ed25519@openssh.com': /^sk-ssh-ed25519@openssh\.com\s+\S+/,
  'ssh-ed25519': /^ssh-ed25519\s+\S+/,
  'ssh-rsa': /^ssh-rsa\s+\S+/,
};

export const sshPublicKeySchema = z.string().superRefine((val, ctx) => {
  const trimmed = val.trim();
  if (trimmed.length === 0) {
    ctx.addIssue({ code: 'custom', message: 'SSH key is required' });
    return;
  }

  if (trimmed.includes('PRIVATE KEY')) {
    ctx.addIssue({
      code: 'custom',
      message: 'This appears to be a private key. Please use the public key (.pub file)',
    });
    return;
  }

  const lines = trimmed.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length > 1) {
    ctx.addIssue({ code: 'custom', message: 'Please enter only one SSH key' });
    return;
  }

  const key = lines[0]?.trim() ?? '';

  for (const [type, pattern] of Object.entries(SSH_KEY_PATTERNS)) {
    if (pattern.test(key)) {
      const parts = key.split(/\s+/);
      const keyData = parts[1] ?? '';
      if (keyData.length < 10) {
        ctx.addIssue({ code: 'custom', message: `SSH key data appears too short for ${type}` });
      }
      return;
    }
  }

  const knownPrefixes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-', 'sk-ssh-', 'sk-ecdsa-'];
  const startsWithKnown = knownPrefixes.some((p) => key.startsWith(p));

  if (startsWithKnown) {
    ctx.addIssue({
      code: 'custom',
      message: 'SSH key format appears invalid. Please check the key data.',
    });
    return;
  }

  ctx.addIssue({
    code: 'custom',
    message: 'Unrecognized SSH key format. Supported: ssh-rsa, ssh-ed25519, ecdsa, sk-ssh-ed25519',
  });
});
// Stryker restore all

/**
 * Extract the comment/name from an SSH public key
 */
export function extractSSHKeyName(pubKey: string): null | string {
  if (!pubKey || typeof pubKey !== 'string') {
    return null;
  }

  const trimmed = pubKey.trim();
  const parts = trimmed.split(/\s+/);

  // SSH key format: type base64data [comment]
  if (parts.length >= 3) {
    const comment = parts.slice(2).join(' ').trim();
    if (comment.length > 0 && comment.length <= 100) {
      return comment;
    }
  }

  return null;
}
