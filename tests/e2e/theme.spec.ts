import { expect, test } from '@playwright/test';

test.describe('Theme', () => {
  test('theme selector opens and shows options', async ({ page }) => {
    await page.goto('/');
    const trigger = page.locator('button[aria-haspopup="true"]');
    await trigger.click();
    await expect(trigger).toHaveAttribute('aria-expanded', 'true');
    // Scope to the dropdown menu, not nav menuitems
    const menuItems = page.locator('[role="menu"] [role="menuitem"]');
    await expect(menuItems.first()).toBeVisible();
    // Should have multiple themes
    expect(await menuItems.count()).toBeGreaterThan(1);
  });

  test('selecting a theme updates the selector', async ({ page }) => {
    await page.goto('/');
    const trigger = page.locator('button[aria-haspopup="true"]');
    await trigger.click();
    // Scope to theme dropdown menu items only
    const themeItems = page.locator('[role="menu"] [role="menuitem"]');
    const secondTheme = themeItems.nth(1);
    const themeName = await secondTheme.textContent();
    expect(themeName).toBeTruthy();
    await secondTheme.click();
    // Menu should close
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    // Button text should contain the selected theme name
    await expect(trigger).toContainText(themeName!.trim());
  });

  test('theme persists on reload', async ({ page }) => {
    await page.goto('/');
    const trigger = page.locator('button[aria-haspopup="true"]');
    await trigger.click();
    // Scope to theme dropdown menu items only
    const themeItems = page.locator('[role="menu"] [role="menuitem"]');
    const secondTheme = themeItems.nth(1);
    const themeName = await secondTheme.textContent();
    expect(themeName).toBeTruthy();
    await secondTheme.click();

    // Reload and check theme persists
    await page.reload();
    await expect(trigger).toContainText(themeName!.trim());
  });
});
