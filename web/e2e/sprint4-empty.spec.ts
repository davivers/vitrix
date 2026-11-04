import { expect, test } from "@playwright/test";

// A repository that was `git init`-ed but has no commit yet (global-setup E2E_EMPTY_URL).
test.use({ baseURL: process.env.E2E_EMPTY_URL });

test("History on a repository without commits shows a friendly message, no raw git text", async ({ page }) => {
  await page.goto("/editor/windows/powershell_encoded.yml");
  await page.getByRole("tab", { name: "History" }).click();
  await expect(page.locator("p:visible", { hasText: "This repository has no commits yet." }).first()).toBeVisible();
  const body = await page.locator("body").innerText();
  expect(body).not.toMatch(/fatal:|does not have any commits|unknown revision|bad revision|ambiguous argument/i);
  await expect(page.getByTestId("sync-chip")).toContainText(/No (commits yet|GitHub remote)/);
});
