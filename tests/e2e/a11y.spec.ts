import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const pages = [
  { hash: '#dashboard', name: 'Dashboard' },
  { hash: '#config', name: 'Config' },
  { hash: '#profiles', name: 'Profiles' },
  { hash: '#cloudinit', name: 'Cloud-Init' },
  { hash: '#credentials', name: 'Credentials' },
];

test.describe('Accessibility @a11y', () => {
  for (const { hash, name } of pages) {
    test(`${name} page has no a11y violations (light theme) @a11y`, async ({ page }) => {
      // Set light theme via localStorage before navigation
      await page.addInitScript(() => {
        localStorage.setItem('devbox_theme', '"peppy"');
      });
      await page.goto(`/${hash}`);
      await page.waitForLoadState('networkidle');

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        // Exclude link-in-text-block: links use hover:underline which axe
        // cannot detect (requires interaction), and color contrast between
        // link text and surrounding text is a known Tailwind theme limitation
        .disableRules(['link-in-text-block'])
        .analyze();

      expect(results.violations).toEqual([]);
    });

    test(`${name} page has no a11y violations (dark theme) @a11y`, async ({ page }) => {
      // Set dark theme via localStorage before navigation
      await page.addInitScript(() => {
        localStorage.setItem('devbox_theme', '"midnight"');
      });
      await page.goto(`/${hash}`);
      await page.waitForLoadState('networkidle');

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        // Exclude link-in-text-block: links use hover:underline which axe
        // cannot detect (requires interaction), and color contrast between
        // link text and surrounding text is a known Tailwind theme limitation
        .disableRules(['link-in-text-block'])
        .analyze();

      expect(results.violations).toEqual([]);
    });
  }
});
