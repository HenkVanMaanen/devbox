import { expect, test } from '@playwright/test';

test.describe('Credentials', () => {
  test('shows API Token heading', async ({ page }) => {
    await page.goto('/#credentials');
    await expect(page.locator('h1')).toHaveText('API Token');
  });

  test('token input is password type', async ({ page }) => {
    await page.goto('/#credentials');
    const tokenInput = page.locator('input[type="password"]');
    await expect(tokenInput).toBeVisible();
  });

  test('Clear All Data opens confirmation modal', async ({ page }) => {
    await page.goto('/#credentials');
    await page.getByRole('button', { name: 'Clear All Data' }).first().click();
    // Modal should appear with confirmation text
    await expect(page.locator('[role="dialog"]')).toBeVisible();
    await expect(page.locator('#modal-title')).toHaveText('Clear All Data');
  });
});
