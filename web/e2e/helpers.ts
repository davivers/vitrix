import { expect, type Page } from "@playwright/test";

export const AUTH_URL = () => process.env.E2E_AUTH_URL!;
export const LOCAL_URL = () => process.env.E2E_LOCAL_URL!;
export const SETUP_TOKEN = () => process.env.E2E_SETUP_TOKEN!;
export const PASSWORD = "correct-horse-battery";

/**
 * Types into the CodeMirror editor with the keyboard, as a new first line (CodeMirror only renders the lines in
 * the viewport, so a marker at the end of a long document would not be visible to text assertions).
 */
export async function appendLine(page: Page, text: string) {
  const cm = page.locator(".cm-content").first();
  await cm.click();
  await page.keyboard.press("Control+Home");
  await page.keyboard.insertText(text);
  await page.keyboard.press("Enter");
  await expect(cm).toContainText(text);
}

/** Owner of the auth server: registers with the setup token the first time, signs in afterwards. */
export async function ownerPage(browser: import("@playwright/test").Browser, baseURL: string) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${baseURL}/?setup=${SETUP_TOKEN()}`);
  await expect(page.getByRole("heading", { name: /Create the first account|Sign in/ })).toBeVisible();
  if (await page.getByRole("heading", { name: "Create the first account" }).isVisible()) {
    await page.getByLabel("Name").fill("Olivia Owner");
    await page.getByLabel("Email").fill("owner@example.com");
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Create the owner account" }).click();
  } else {
    await page.getByLabel("Email").fill("owner@example.com");
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).last().click();
  }
  await expect(page.getByRole("button", { name: /Account menu/ })).toBeVisible();
  return { ctx, page };
}

/** Invites `email` with `role` (through the API as the owner) and registers that user in a new context. */
export async function invitedPage(browser: import("@playwright/test").Browser, owner: import("@playwright/test").BrowserContext, baseURL: string, email: string, name: string, role: string) {
  const inv = await owner.request.post(`${baseURL}/api/workspace/invites`, { data: { email, role } });
  expect(inv.ok(), await inv.text()).toBeTruthy();
  const link = new URL((await inv.json()).link);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${baseURL}${link.pathname}${link.search}`);
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).last().click();
  await expect(page.getByRole("button", { name: /Account menu/ })).toBeVisible();
  return { ctx, page };
}
