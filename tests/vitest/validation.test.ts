import { describe, expect, it } from 'vitest';

import { sshPublicKeySchema } from '$lib/utils/validation';

function validate(key: string) {
  return sshPublicKeySchema.safeParse(key);
}

describe('sshPublicKeySchema - key type patterns', () => {
  it('accepts ssh-ed25519 key', () => {
    expect(validate('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host').success).toBe(true);
  });

  it('accepts ssh-rsa key', () => {
    expect(validate('ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@host').success).toBe(true);
  });

  it('accepts ecdsa-sha2-nistp256 key', () => {
    // cspell:disable-next-line
    expect(validate('ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItest256 user@host').success).toBe(true);
  });

  it('accepts ecdsa-sha2-nistp384 key', () => {
    // cspell:disable-next-line
    expect(validate('ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItest384 user@host').success).toBe(true);
  });

  it('accepts ecdsa-sha2-nistp521 key', () => {
    // cspell:disable-next-line
    expect(validate('ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItest521 user@host').success).toBe(true);
  });

  it('accepts sk-ecdsa-sha2-nistp256@openssh.com key', () => {
    expect(
      validate('sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20 user@host')
        .success,
    ).toBe(true);
  });

  it('accepts sk-ssh-ed25519@openssh.com key', () => {
    expect(validate('sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t user@host').success).toBe(
      true,
    );
  });
});

describe('sshPublicKeySchema - error cases', () => {
  it('rejects empty input', () => {
    const result = validate('');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('SSH key is required');
  });

  it('rejects whitespace-only input', () => {
    const result = validate('   \n  ');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('SSH key is required');
  });

  it('rejects private key (BEGIN PRIVATE KEY)', () => {
    const result = validate('-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('private key');
  });

  it('rejects RSA private key', () => {
    const result = validate('-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('private key');
  });

  it('rejects multiple keys (multiple lines)', () => {
    const result = validate('ssh-ed25519 AAAA key1\nssh-ed25519 BBBB key2');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('Please enter only one SSH key');
  });

  it('rejects key with very short key data (< 10 chars)', () => {
    const result = validate('ssh-ed25519 SHORT user@host');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('too short');
    expect(result.error?.issues[0]?.message).toContain('ssh-ed25519');
  });

  it('rejects rsa key with short data', () => {
    const result = validate('ssh-rsa abc user@host');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('too short');
    expect(result.error?.issues[0]?.message).toContain('ssh-rsa');
  });

  it('rejects key starting with known prefix but invalid format (no key data)', () => {
    const result = validate('ssh-rsa');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('format appears invalid');
  });

  it('rejects key with ssh-ed25519 prefix but no key data', () => {
    const result = validate('ssh-ed25519');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('format appears invalid');
  });

  it('rejects key with ecdsa-sha2- prefix but no key data', () => {
    const result = validate('ecdsa-sha2-nistp256');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('format appears invalid');
  });

  it('rejects key with sk-ssh- prefix but no key data', () => {
    const result = validate('sk-ssh-ed25519@openssh.com');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('format appears invalid');
  });

  it('rejects key with sk-ecdsa- prefix but no key data', () => {
    const result = validate('sk-ecdsa-sha2-nistp256@openssh.com');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('format appears invalid');
  });

  it('rejects completely unknown format', () => {
    const result = validate('not-a-key');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('Unrecognized SSH key format');
  });

  it('rejects random text', () => {
    const result = validate('hello world this is not a key');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('Unrecognized');
  });
});

describe('sshPublicKeySchema - issue code property (kills code: "custom" → code: "" mutants)', () => {
  it('empty input issue has code "custom"', () => {
    const result = validate('');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });

  it('private key issue has code "custom"', () => {
    const result = validate('-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });

  it('multiple keys issue has code "custom"', () => {
    const result = validate('ssh-ed25519 AAAA key1\nssh-ed25519 BBBB key2');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });

  it('short key data issue has code "custom"', () => {
    const result = validate('ssh-ed25519 SHORT user@host');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });

  it('known prefix but invalid format issue has code "custom"', () => {
    const result = validate('ssh-rsa');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });

  it('unrecognized format issue has code "custom"', () => {
    const result = validate('not-a-key');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('custom');
  });
});

describe('sshPublicKeySchema - filter and trim mutations', () => {
  it('blank lines are filtered out (kills filter length > 0 mutant)', () => {
    // Input with blank lines between - should still parse as a single key
    const result = validate('\n\n  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host\n\n');
    expect(result.success).toBe(true);
  });

  it('lines with only whitespace are filtered (filter l.trim().length > 0)', () => {
    // Lines that are just spaces should be treated as blank
    const result = validate('   \n  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host\n   ');
    expect(result.success).toBe(true);
  });

  it('multiple non-empty lines after filtering triggers multi-key error', () => {
    // If filter was removed, lines with blank content would count, changing behavior
    const result = validate('ssh-ed25519 AAAAAAAAAA key1\n\nssh-ed25519 BBBBBBBBBB key2');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('Please enter only one SSH key');
  });

  it('key line is trimmed before pattern matching (kills lines[0]?.trim() → lines[0])', () => {
    // Key with leading spaces on the line itself
    const result = validate('  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host');
    expect(result.success).toBe(true);
  });
});

describe('sshPublicKeySchema - split regex and slice/trim', () => {
  it('key split uses \\s+ to handle multiple spaces (kills \\s+ → \\s)', () => {
    // Key with multiple spaces between parts - \s+ matches all, \s would only match one
    const result = validate('ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAItest  user@host');
    expect(result.success).toBe(true);
  });

  it('key with tabs split correctly (\\s+ matches tabs)', () => {
    // cspell:disable-next-line
    const result = validate('ssh-ed25519\t\tAAAAC3NzaC1lZDI1NTE5AAAAItest\tuser@host');
    expect(result.success).toBe(true);
  });
});

describe('sshPublicKeySchema - edge cases', () => {
  it('accepts key without comment', () => {
    const result = validate('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest');
    expect(result.success).toBe(true);
  });

  it('accepts key with whitespace padding', () => {
    const result = validate('  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host  ');
    expect(result.success).toBe(true);
  });

  it('accepts key with empty lines around it', () => {
    const result = validate('\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host\n');
    expect(result.success).toBe(true);
  });

  it('key data exactly 10 chars is accepted', () => {
    const result = validate('ssh-ed25519 1234567890 user@host');
    expect(result.success).toBe(true);
  });

  it('key data 9 chars is rejected as too short', () => {
    const result = validate('ssh-ed25519 123456789 user@host');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('too short');
  });
});
