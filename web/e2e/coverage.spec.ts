import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

test.use({ baseURL: process.env.E2E_LOCAL_URL });

test("matrix renders, technique drawer opens and Esc closes it", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByRole("heading", { name: "MITRE ATT&CK coverage" })).toBeVisible();
  const cell = page.getByRole("button", { name: /^T1059/ }).first();
  await expect(cell).toBeVisible();
  await cell.click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText("PowerShell with an encoded command")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
});

test("Navigator layer downloads a file", async ({ page }) => {
  await page.goto("/coverage");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: /Navigator/ }).click()]);
  expect(dl.suggestedFilename()).toBe("vitrix-attack-layer.json");
  const layer = JSON.parse(readFileSync(await dl.path(), "utf8"));
  expect(Array.isArray(layer.techniques)).toBe(true);
  expect(layer.techniques.length).toBeGreaterThan(0);
});

test("gaps: catalogue tile and the Gaps filter list uncovered techniques", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByText("Catalogue coverage")).toBeVisible();
  await expect(page.getByText(/^\d+ of \d+$/).first()).toBeVisible();
  await expect(page.getByText(/Gaps are measured against the local MITRE ATT&CK Enterprise catalogue/)).toBeVisible();
  const gaps = page.getByRole("button", { name: "Gaps", exact: true });
  await expect(gaps).toBeEnabled();
  await gaps.click();
  await expect(gaps).toHaveAttribute("aria-pressed", "true");
  const uncovered = page.getByRole("button", { name: /, 0 rules/ });
  await expect(uncovered.first()).toBeVisible();
  expect(await uncovered.count()).toBeGreaterThan(20);
});
