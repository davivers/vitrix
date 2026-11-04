import { expect, test } from "@playwright/test";
import { invitedPage, ownerPage } from "./helpers";

test.use({ baseURL: process.env.E2E_AUTH_URL });

// Works standalone or after accounts.spec.ts (the owner may already exist).
test("a viewer can use the regex workbench", async ({ browser, baseURL }) => {
  const owner = await ownerPage(browser, baseURL!);
  const viewer = await invitedPage(browser, owner.ctx, baseURL!, "vera@example.com", "Vera Viewer", "viewer");
  const page = viewer.page;

  await page.goto("/regex");
  await page.locator("input.font-mono").first().fill("pass(word|wd)\\d+");
  const done = page.waitForResponse((r) => r.url().includes("/api/regex") && r.request().postData()?.includes("password123") === true);
  await page.getByRole("textbox", { name: "Sample 1" }).fill("my password123 here");
  const resp = await done; // the viewer is allowed to call it (G3)
  expect(resp.status()).toBe(200);
  expect(JSON.parse(resp.request().postData()!).engine).toBe("python-regex"); // the default engine
  await expect(page.getByLabel("Regex engine")).toBeVisible();
  await expect(page.getByText(/matched/i).first()).toBeVisible();
  await expect(page.getByText("Invalid regex")).toHaveCount(0);
  await owner.ctx.close();
  await viewer.ctx.close();
});
