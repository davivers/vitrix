import { expect, test } from "@playwright/test";
import { AUTH_URL, PASSWORD, SETUP_TOKEN } from "./helpers";

test.use({ baseURL: process.env.E2E_AUTH_URL });
test.describe.configure({ mode: "serial" });

test("first run needs the setup token; the setup link registers the owner and is stripped from the URL", async ({ browser, baseURL }) => {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await p.goto("/");
  await expect(p.getByText("Setup link required")).toBeVisible();
  await p.getByLabel("Name").fill("Mallory");
  await p.getByLabel("Email").fill("mallory@example.com");
  await p.getByLabel("Password").fill(PASSWORD);
  await p.getByLabel("Setup token").fill("wrong-token-wrong-token");
  await p.getByRole("button", { name: "Create the owner account" }).click();
  await expect(p.getByText(/setup token/i).last()).toBeVisible();
  await expect(p.getByRole("button", { name: /Account menu/ })).toHaveCount(0);
  // API: no token -> refused.
  const r = await ctx.request.post(`${baseURL}/api/auth/register`, { data: { email: "mallory@example.com", name: "Mallory", password: PASSWORD } });
  expect(r.status()).toBeGreaterThanOrEqual(400);
  await ctx.close();
});

test("owner bootstraps, invites an editor, role changes keep the session", async ({ browser, page, baseURL }) => {
  // 1. First screen: create the owner account.
  await page.goto(`/?setup=${SETUP_TOKEN()}`);
  await expect(page.getByRole("heading", { name: "Create the first account" })).toBeVisible();
  await page.getByLabel("Name").fill("Olivia Owner");
  await page.getByLabel("Email").fill("owner@example.com");
  await page.getByLabel("Password").fill(PASSWORD);
  await expect(page).not.toHaveURL(/setup=/); // the token is stripped from the address bar
  await page.getByRole("button", { name: "Create the owner account" }).click();
  await expect(page.getByRole("button", { name: /Account menu/ })).toBeVisible();
  expect(page.url()).not.toContain("setup=");

  // 2. Team -> create an editor invite -> read the link.
  await page.goto("/team");
  await page.getByPlaceholder("colleague@company.com").fill("eddie@example.com");
  await page.locator("form select").selectOption("editor");
  await page.getByRole("button", { name: "Create invite" }).click();
  const link = page.getByLabel("Invite link");
  await expect(link).toBeVisible();
  await page.getByRole("button", { name: "Copy", exact: true }).click(); // clipboard may be denied; the link stays selectable
  const inviteUrl = await link.inputValue();
  expect(inviteUrl).toContain("invite=");

  // 3. Second browser context opens the link and registers.
  const ctx2 = await browser.newContext();
  const eddie = await ctx2.newPage();
  const u = new URL(inviteUrl);
  await eddie.goto(`${baseURL}${u.pathname}${u.search}`);
  await expect(eddie.getByRole("heading", { name: "Accept your invitation" })).toBeVisible();
  await eddie.getByLabel("Name").fill("Eddie Editor");
  await eddie.getByLabel("Email").fill("eddie@example.com");
  await eddie.getByLabel("Password").fill(PASSWORD);
  await eddie.getByRole("button", { name: "Create account" }).last().click();
  await expect(eddie.getByRole("button", { name: /Account menu/ })).toBeVisible();

  // The editor can save locally.
  await eddie.goto("/editor");
  await expect(eddie.getByRole("button", { name: "Save locally" })).not.toHaveAttribute("aria-disabled", "true");

  // 4. Owner changes Eddie to viewer.
  await page.goto("/team");
  const roleSelect = page.getByLabel("Role of Eddie Editor");
  await roleSelect.selectOption("viewer");
  await expect(roleSelect).toHaveValue("viewer");

  // 5. Eddie is NOT logged out; the UI turns read-only (after the next /api/me refresh).
  await eddie.reload();
  await expect(eddie.getByRole("button", { name: /Account menu/ })).toBeVisible();
  await expect(eddie.getByRole("heading", { name: "Sign in" })).toHaveCount(0);
  await expect(eddie.getByRole("button", { name: "Save locally" })).toHaveAttribute("aria-disabled", "true");
  await expect(eddie.getByText("Save locally: saving needs the editor role.")).toBeVisible();

  // 6. Back to editor: Eddie can save again, still without signing in again.
  await roleSelect.selectOption("editor");
  await expect(roleSelect).toHaveValue("editor");
  await eddie.reload();
  const save = eddie.getByRole("button", { name: "Save locally" });
  await expect(save).not.toHaveAttribute("aria-disabled", "true");
  await save.click();
  await expect(eddie.getByText(/Saved locally at/)).toBeVisible();
  await ctx2.close();
});

test("without an invite there is no way to create an account", async ({ browser, baseURL }) => {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await p.goto(baseURL!);
  await expect(p.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(p.getByRole("button", { name: "Create account" })).toHaveCount(0);
  await expect(p.getByRole("tab", { name: "Create account" })).toHaveCount(0);
  await expect(p.getByText(/Registration is by invitation/)).toBeVisible();
  // The API also refuses open sign-up.
  const r = await ctx.request.post(`${AUTH_URL()}/api/auth/register`, { data: { email: "mallory@example.com", name: "Mallory", password: PASSWORD } });
  expect(r.status()).toBeGreaterThanOrEqual(400);
  expect(r.status()).toBeLessThan(500);
  await ctx.close();
});
