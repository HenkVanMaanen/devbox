import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { buildGitCredentials, shellEscape, toBase64URL } from '$lib/utils/cloudinit-builders';
import { mergeCustomCloudInit, BLOCKED_CUSTOM_KEYS } from '$lib/utils/cloudinit';
import { clone, deepMerge, getNestedValue, setNestedValue } from '$lib/utils/storage';
import { sshPublicKeySchema } from '$lib/utils/validation';

describe('Property-based tests', () => {
  describe('shellEscape', () => {
    it('never contains unescaped dangerous characters', () => {
      fc.assert(
        fc.property(fc.string(), (s) => {
          const result = shellEscape(s);
          // Remove all escaped sequences (backslash followed by char)
          const unescaped = result.replace(/\\./g, '');
          // The unescaped remainder should not contain any dangerous chars
          expect(unescaped).not.toMatch(/["$`!]/);
        }),
      );
    });

    it('never contains newlines', () => {
      fc.assert(
        fc.property(fc.string(), (s) => {
          expect(shellEscape(s)).not.toContain('\n');
        }),
      );
    });

    it('passes through alphanumeric strings unchanged', () => {
      fc.assert(
        fc.property(fc.stringMatching(/^[a-zA-Z0-9]*$/), (s) => {
          expect(shellEscape(s)).toBe(s);
        }),
      );
    });

    it('returns empty string for empty input', () => {
      expect(shellEscape('')).toBe('');
    });
  });

  describe('buildGitCredentials', () => {
    it('returns empty string when any field is empty', () => {
      fc.assert(
        fc.property(fc.string(), fc.string(), (a, b) => {
          expect(buildGitCredentials({ host: '', username: a, token: b })).toBe('');
          expect(buildGitCredentials({ host: a, username: '', token: b })).toBe('');
          expect(buildGitCredentials({ host: a, username: b, token: '' })).toBe('');
        }),
      );
    });

    it('output is valid URL format when all fields non-empty', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }).filter((s) => /[a-zA-Z0-9]/.test(s)),
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          (host, username, token) => {
            const result = buildGitCredentials({ host, username, token });
            if (result === '') return; // host might become empty after sanitization
            expect(result).toMatch(/^https:\/\/.+:.+@[a-zA-Z0-9._-]+\n$/);
          },
        ),
      );
    });

    it('host contains only valid hostname characters', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }).filter((s) => /[a-zA-Z0-9._-]/.test(s)),
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          (host, username, token) => {
            const result = buildGitCredentials({ host, username, token });
            if (result === '') return;
            const hostPart = result.split('@')[1]?.replace('\n', '') ?? '';
            expect(hostPart).toMatch(/^[a-zA-Z0-9._-]+$/);
          },
        ),
      );
    });
  });

  describe('toBase64URL', () => {
    it('output never contains +, /, or trailing =', () => {
      fc.assert(
        fc.property(fc.string(), (s) => {
          const result = toBase64URL(s);
          expect(result).not.toContain('+');
          expect(result).not.toContain('/');
          expect(result).not.toMatch(/=+$/);
        }),
      );
    });

    it('returns empty for empty/falsy input', () => {
      expect(toBase64URL('')).toBe('');
    });
  });

  describe('getNestedValue / setNestedValue roundtrip', () => {
    it('set then get returns the same value for valid paths', () => {
      // Generate simple dot-notation paths with 1-3 segments
      const pathArb = fc
        .array(fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9]*$/), { minLength: 1, maxLength: 3 })
        .map((parts) => parts.join('.'));

      const valueArb = fc.oneof(fc.string(), fc.integer(), fc.boolean(), fc.constant(null));

      fc.assert(
        fc.property(pathArb, valueArb, (path, value) => {
          const obj: Record<string, unknown> = {};
          setNestedValue(obj, path, value);
          expect(getNestedValue(obj, path)).toEqual(value);
        }),
      );
    });
  });

  describe('clone', () => {
    it('produces deep-equal copy of any JSON value', () => {
      fc.assert(
        fc.property(fc.jsonValue(), (value) => {
          const cloned = clone(value);
          // Normalize -0 to 0 since structuredClone may not preserve -0
          const normalized = JSON.parse(JSON.stringify(value)) as typeof value;
          expect(cloned).toEqual(normalized);
        }),
      );
    });

    it('clone is independent of original for objects', () => {
      fc.assert(
        fc.property(
          fc.record({
            a: fc.string(),
            b: fc.integer(),
          }),
          (obj) => {
            const cloned = clone(obj);
            cloned.a = 'modified';
            expect(obj.a).not.toBe('modified');
          },
        ),
      );
    });
  });

  describe('deepMerge', () => {
    it('result contains all keys from target', () => {
      fc.assert(
        fc.property(
          fc.record({
            a: fc.string(),
            b: fc.integer(),
            c: fc.boolean(),
          }),
          fc.record({
            a: fc.string(),
          }),
          (target, source) => {
            const result = deepMerge(target, source);
            for (const key of Object.keys(target)) {
              expect(key in result).toBe(true);
            }
          },
        ),
      );
    });
  });

  describe('mergeCustomCloudInit', () => {
    it('blocked keys are never overridden by custom YAML', () => {
      const blockedKeys = [...BLOCKED_CUSTOM_KEYS];
      fc.assert(
        fc.property(fc.constantFrom(...blockedKeys), fc.string(), (key, value) => {
          const base: Record<string, unknown> = {
            [key]: 'original',
            packages: ['git'],
            runcmd: ['/usr/local/bin/devbox-progress ready'],
          };
          const yaml = `${key}: ${JSON.stringify(value)}`;
          const result = mergeCustomCloudInit(base, yaml);
          expect(result[key]).toBe('original');
        }),
      );
    });

    it('custom packages are merged without duplicates', () => {
      fc.assert(
        fc.property(fc.array(fc.stringMatching(/^[a-z][a-z0-9-]*$/), { minLength: 1, maxLength: 5 }), (packages) => {
          const base: Record<string, unknown> = {
            packages: ['git', 'curl'],
            runcmd: [],
          };
          const yaml = `packages:\n${packages.map((p) => `  - ${p}`).join('\n')}`;
          const result = mergeCustomCloudInit(base, yaml);
          const resultPkgs = result['packages'] as string[];
          // All base packages should be present
          expect(resultPkgs).toContain('git');
          expect(resultPkgs).toContain('curl');
          // No duplicates
          expect(new Set(resultPkgs).size).toBe(resultPkgs.length);
        }),
      );
    });
  });

  describe('sshPublicKeySchema', () => {
    it('rejects random non-SSH strings', () => {
      fc.assert(
        fc.property(
          fc
            .string({ minLength: 1, maxLength: 100 })
            .filter(
              (s) => !s.startsWith('ssh-') && !s.startsWith('ecdsa-') && !s.startsWith('sk-') && s.trim().length > 0,
            ),
          (s) => {
            const result = sshPublicKeySchema.safeParse(s);
            expect(result.success).toBe(false);
          },
        ),
      );
    });

    it('accepts well-formed ed25519 keys', () => {
      // Generate a base64-like string for key data
      fc.assert(
        fc.property(fc.stringMatching(/^[A-Za-z0-9+/]{44}$/), (keyData) => {
          const key = `ssh-ed25519 ${keyData}`;
          const result = sshPublicKeySchema.safeParse(key);
          expect(result.success).toBe(true);
        }),
        { numRuns: 20 },
      );
    });
  });
});
