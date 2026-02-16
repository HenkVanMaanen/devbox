import { describe, expect, it } from 'vitest';

import { generateServerName } from '$lib/utils/names';

describe('generateServerName', () => {
  it('returns a string in adjective-noun format with a hyphen separator', () => {
    const name = generateServerName();
    const parts = name.split('-');
    expect(parts).toHaveLength(2);
    expect(parts[0]?.length).toBeGreaterThan(0);
    expect(parts[1]?.length).toBeGreaterThan(0);
  });

  it('generates different names across multiple calls', () => {
    const names = new Set<string>();
    for (let i = 0; i < 20; i++) {
      names.add(generateServerName());
    }
    expect(names.size).toBeGreaterThanOrEqual(2);
  });

  it('produces lowercase names only', () => {
    for (let i = 0; i < 10; i++) {
      const name = generateServerName();
      expect(name).toBe(name.toLowerCase());
    }
  });

  it('both parts contain only alphabetic characters', () => {
    const pattern = /^[a-z]+$/;
    for (let i = 0; i < 10; i++) {
      const name = generateServerName();
      const [adjective, noun] = name.split('-');
      expect(adjective).toMatch(pattern);
      expect(noun).toMatch(pattern);
    }
  });
});
