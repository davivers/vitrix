import { expect, test } from "@playwright/test";

test.use({ baseURL: process.env.E2E_LOCAL_URL });

// The packs cache is pre-seeded by global-setup (3 fixture SigmaHQ rules), so no network is used.
test("content packs: preview, import 2 rules as local files, open one in the Editor", async ({ page, request, baseURL }) => {
  await page.goto("/packs");
  await expect(page.getByRole("heading", { name: "Content packs" })).toBeVisible();
  await page.getByRole("button", { name: "Find matching rules" }).click();
  await expect(page.getByText(/3 rules match/)).toBeVisible();
  const three = page.getByRole("checkbox", { name: "E2E fixture tool three" });
  await expect(three).toBeChecked();
  await three.uncheck();
  await page.getByRole("button", { name: /Import 2/ }).click();
  await expect(page.getByRole("heading", { name: /^2 (drafts|rules) (created|imported|saved)/ })).toBeVisible();

  const rules = await (await request.get(`${baseURL}/api/rules`)).json();
  const items = (Array.isArray(rules) ? rules : rules.rules) as { title: string }[];
  expect(items.filter((r) => r.title.startsWith("E2E fixture"))).toHaveLength(2);

  await page.getByRole("link", { name: /E2E fixture tool (one|two)/ }).first().click();
  await expect(page).toHaveURL(/\/editor\//);
  await expect(page.locator(".cm-content").first()).toContainText("E2E fixture tool");
});
