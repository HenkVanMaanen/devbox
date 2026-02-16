import { describe, expect, it } from 'vitest';

import { generateQR } from '$lib/utils/qrcode';

describe('generateQR', () => {
  it('returns a valid SVG string', () => {
    const svg = generateQR('https://example.com');
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg).toContain('viewBox');
  });

  it('produces different SVGs for different inputs', () => {
    const svg1 = generateQR('hello');
    const svg2 = generateQR('world');
    expect(svg1).not.toBe(svg2);
  });

  it('handles special characters', () => {
    const svg = generateQR('https://user:p@ss@example.com/path?q=1&r=2');
    expect(svg).toContain('<svg');
  });
});
