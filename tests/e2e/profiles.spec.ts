import { expect, test } from '@playwright/test';

test.describe('Profiles', () => {
  test('shows Profiles heading', async ({ page }) => {
    await page.goto('/#profiles');
    await expect(page.locator('h1')).toHaveText('Profiles');
  });

  test('shows empty state message', async ({ page }) => {
    await page.goto('/#profiles');
    await expect(page.getByText('No profiles yet')).toBeVisible();
  });

  test('New Profile modal opens', async ({ page }) => {
    await page.goto('/#profiles');
    await page.getByRole('button', { name: 'New Profile' }).click();
    await expect(page.locator('[role="dialog"]')).toBeVisible();
    await expect(page.locator('#modal-title')).toHaveText('Create Profile');
  });

  test('creating a profile navigates to edit', async ({ page }) => {
    await page.goto('/#profiles');
    await page.getByRole('button', { name: 'New Profile' }).click();
    await expect(page.locator('[role="dialog"]')).toBeVisible();
    await page.locator('[role="dialog"] input').fill('Test Profile');
    // Click Create within the dialog
    await page.locator('[role="dialog"]').getByRole('button', { name: 'Create' }).click();
    // Should navigate to profile edit page
    await expect(page).toHaveURL(/#profiles\/.+/);
  });
});
