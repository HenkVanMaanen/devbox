// Validation utilities for form fields and SSH keys

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

export interface ValidationResult {
  error?: null | string;
  type?: null | string;
  valid: boolean;
}

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

/**
 * Validate an email address
 */
export function validateEmail(value: string): ValidationResult {
  if (!value || value.trim().length === 0) {
    return { error: null, valid: true }; // Empty is valid (optional)
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(value)) {
    return { error: 'Please enter a valid email address', valid: false };
  }
  return { error: null, valid: true };
}

/**
 * Validate JSON string
 */
export function validateJSON(value: string): ValidationResult {
  if (!value || value.trim().length === 0) {
    return { error: null, valid: true }; // Empty is valid
  }

  try {
    JSON.parse(value);
    return { error: null, valid: true };
  } catch (error) {
    return { error: `Invalid JSON: ${(error as Error).message}`, valid: false };
  }
}

/**
 * Validate an SSH public key
 */
export function validateSSHKey(pubKey: string): ValidationResult {
  if (!pubKey || typeof pubKey !== 'string') {
    return { error: 'SSH key is required', type: null, valid: false };
  }

  const trimmed = pubKey.trim();
  if (trimmed.length === 0) {
    return { error: 'SSH key is required', type: null, valid: false };
  }

  // Check if it looks like a private key (common mistake)
  if (trimmed.includes('PRIVATE KEY')) {
    return {
      error: 'This appears to be a private key. Please use the public key (.pub file)',
      type: null,
      valid: false,
    };
  }

  // Check if it looks like an authorized_keys file with multiple keys
  const lines = trimmed.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length > 1) {
    return { error: 'Please enter only one SSH key', type: null, valid: false };
  }

  const key = lines[0]?.trim() ?? '';

  // Try to match against known key types
  for (const [type, pattern] of Object.entries(SSH_KEY_PATTERNS)) {
    if (pattern.test(key)) {
      // Extract the base64 data part
      const parts = key.split(/\s+/);
      const keyData = parts[1] ?? '';

      if (keyData.length < 10) {
        return { error: `SSH key data appears too short for ${type}`, type, valid: false };
      }

      return { error: null, type, valid: true };
    }
  }

  // Check if it starts with a known prefix but is malformed
  const knownPrefixes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-', 'sk-ssh-', 'sk-ecdsa-'];
  const startsWithKnown = knownPrefixes.some((p) => key.startsWith(p));

  if (startsWithKnown) {
    return { error: 'SSH key format appears invalid. Please check the key data.', type: null, valid: false };
  }

  return {
    error: 'Unrecognized SSH key format. Supported: ssh-rsa, ssh-ed25519, ecdsa, sk-ssh-ed25519',
    type: null,
    valid: false,
  };
}
