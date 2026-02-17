import { expect, test } from '@playwright/test';

test.describe('Navigation', () => {
  test('default page is dashboard', async ({ page }) => {
    await page.goto('/');
    // Dashboard is the default - nav link should have aria-current="page"
    const dashboardLink = page.locator('nav a[href="#dashboard"]');
    await expect(dashboardLink).toHaveAttribute('aria-current', 'page');
  });

  test('nav links navigate between pages', async ({ page }) => {
    await page.goto('/');

    // Click each nav link and verify it becomes active
    const navItems = [
      { href: '#credentials', label: 'API Token' },
      { href: '#profiles', label: 'Profiles' },
      { href: '#config', label: 'Global' },
      { href: '#cloudinit', label: 'Cloud-Init' },
      { href: '#dashboard', label: 'Dashboard' },
    ];

    for (const item of navItems) {
      // Scope to nav element to avoid matching in-page links
      const link = page.locator(`nav a[href="${item.href}"]`);
      await link.click();
      await expect(link).toHaveAttribute('aria-current', 'page');
    }
  });

  test('direct hash navigation works', async ({ page }) => {
    await page.goto('/#credentials');
    await expect(page.locator('h1')).toHaveText('API Token');
  });

  test('unknown hash shows no page content', async ({ page }) => {
    await page.goto('/#nonexistent');
    // App does not fall back - no page content should be rendered
    // but the nav should still be visible
    await expect(page.locator('nav')).toBeVisible();
    // No nav link should have aria-current="page"
    const activeLinks = page.locator('nav a[aria-current="page"]');
    await expect(activeLinks).toHaveCount(0);
  });
});
