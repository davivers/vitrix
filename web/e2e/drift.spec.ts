import { expect, test } from "@playwright/test";

test.use({ baseURL: process.env.E2E_LOCAL_URL });

test("Editor Drift tab compares an example rule with a Git ref", async ({ page }) => {
  await page.goto("/editor/windows/powershell_encoded.yml");
  await page.getByRole("tab", { name: "Drift" }).click();
  await page.getByPlaceholder("default: origin/main").fill("HEAD");
  await page.getByRole("button", { name: "Compare" }).click();
  await expect(page.getByText("Compared with")).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Dataset" })).toBeVisible();
  await expect(page.getByText("windows_attack_simulation")).toBeVisible();
});

test("Rules page Drift toggle", async ({ page }) => {
  await page.goto("/rules");
  await page.getByRole("button", { name: "Drift", exact: true }).click();
  await page.getByPlaceholder("default: origin/main").fill("HEAD");
  await page.getByRole("button", { name: "Compare" }).click();
  await expect(page.getByText(/rules drifted/)).toBeVisible();
});
