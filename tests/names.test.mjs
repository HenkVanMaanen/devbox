import { describe, it } from 'node:test';
import assert from 'node:assert';

import { generateServerName } from '../src/lib/utils/names.ts';

describe('generateServerName', () => {
  it('returns a string in adjective-noun format with exactly one hyphen', () => {
    const name = generateServerName();
    const parts = name.split('-');
    assert.equal(parts.length, 2, `Expected exactly one hyphen in "${name}"`);
    assert.ok(parts[0].length > 0, 'Adjective part should be non-empty');
    assert.ok(parts[1].length > 0, 'Noun part should be non-empty');
  });

  it('generates different names across multiple calls', () => {
    const names = new Set();
    for (let i = 0; i < 20; i++) {
      names.add(generateServerName());
    }
    assert.ok(names.size >= 2, `Expected at least 2 unique names but got ${names.size}`);
  });

  it('both parts are non-empty strings', () => {
    for (let i = 0; i < 10; i++) {
      const name = generateServerName();
      const [adjective, noun] = name.split('-');
      assert.ok(typeof adjective === 'string' && adjective.length > 0, 'Adjective must be a non-empty string');
      assert.ok(typeof noun === 'string' && noun.length > 0, 'Noun must be a non-empty string');
    }
  });

  it('adjective and noun are lowercase alphabetic only', () => {
    const pattern = /^[a-z]+$/;
    for (let i = 0; i < 10; i++) {
      const name = generateServerName();
      const [adjective, noun] = name.split('-');
      assert.match(adjective, pattern, `Adjective "${adjective}" should be lowercase alphabetic`);
      assert.match(noun, pattern, `Noun "${noun}" should be lowercase alphabetic`);
    }
  });

  it('can produce alliterative names where both parts start with the same letter', () => {
    let foundAlliterative = false;
    for (let i = 0; i < 100; i++) {
      const name = generateServerName();
      const [adjective, noun] = name.split('-');
      if (adjective[0] === noun[0]) {
        foundAlliterative = true;
        break;
      }
    }
    assert.ok(foundAlliterative, 'Expected at least one alliterative name in 100 attempts');
  });

  it('produces deterministic alliterative name with known random seed', () => {
    const originalRandom = Math.random;
    Math.random = () => 0.5;
    try {
      const name = generateServerName();
      // With Math.random=0.5: floor(0.5*26)=13 → letter 'n'
      // adjectives starting with 'n': ['nice'], nouns: ['narwhal']
      assert.strictEqual(name, 'nice-narwhal');
    } finally {
      Math.random = originalRandom;
    }
  });
});
