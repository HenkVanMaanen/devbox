import { expect, test } from '@playwright/test';

test.describe('Config', () => {
  test('shows Global page content', async ({ page }) => {
    await page.goto('/#config');
    // The Global nav link should be active
    const globalLink = page.locator('a[href="#config"]');
    await expect(globalLink).toHaveAttribute('aria-current', 'page');
  });

  test('export button is visible', async ({ page }) => {
    await page.goto('/#config');
    await expect(page.getByRole('button', { name: /export/i })).toBeVisible();
  });

  test('import button is visible', async ({ page }) => {
    await page.goto('/#config');
    await expect(page.getByRole('button', { name: /import/i })).toBeVisible();
  });
});
