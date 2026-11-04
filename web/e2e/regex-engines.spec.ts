import { expect, test, type Page } from "@playwright/test";

// Regex Workbench engines (U6 revised): per-engine behaviour, JavaScript in a Web Worker, persisted choice.
test.use({ baseURL: process.env.E2E_LOCAL_URL });

async function setup(page: Page, pattern: string, sample: string) {
  await page.locator("input.font-mono").first().fill(pattern);
  await page.getByRole("textbox", { name: "Sample 1" }).fill(sample);
}
const engineSelect = (page: Page) => page.getByLabel("Regex engine");

test("RE2 rejects a lookahead with the engine's own message, never '(position null)'", async ({ page }) => {
  await page.goto("/regex");
  await engineSelect(page).selectOption("re2");
  await setup(page, "foo(?=bar)", "foobar");
  const msg = page.getByText(/invalid perl operator|invalid|missing argument/i).first();
  await expect(msg).toBeVisible();
  const body = await page.locator("body").innerText();
  expect(body).not.toMatch(/position null|position undefined|\(position\s*\)/i);
  await expect(page.getByTestId("regex-flavor-scan")).toHaveCount(0);
});

test("PCRE2 and python-regex match the same simple pattern", async ({ page }) => {
  await page.goto("/regex");
  for (const id of ["python-regex", "pcre2"]) {
    await engineSelect(page).selectOption(id);
    await setup(page, "pass(word|wd)\d+", "my password123 here");
    await expect(page.getByText(/matched \(1\)/).first()).toBeVisible();
    await expect(page.getByTestId("regex-engine")).toContainText(id === "pcre2" ? /PCRE/i : /Python regex/);
  }
});

test("JavaScript engine matches in the browser; a catastrophic pattern is stopped by the worker timeout and the page stays responsive", async ({ page }) => {
  const apiCalls: string[] = [];
  page.on("request", (r) => r.url().includes("/api/regex") && r.method() === "POST" && apiCalls.push(r.postData() ?? ""));
  await page.goto("/regex");
  await engineSelect(page).selectOption({ label: /JavaScript/ });
  await page.waitForTimeout(600);
  apiCalls.length = 0;
  await setup(page, "pass(word|wd)\d+", "my password123 here");
  await expect(page.getByText(/matched \(1\)/).first()).toBeVisible();
  await expect(page.getByTestId("regex-engine")).toContainText(/JavaScript/);
  expect(apiCalls).toHaveLength(0); // nothing was sent to the server: it ran in the browser

  await setup(page, "^(a+)+$", "a".repeat(40) + "!");
  await expect(page.getByText(/timed out after \d+ ?ms/i).first()).toBeVisible({ timeout: 15_000 });
  // The page still responds: edit the pattern and get a result again.
  await setup(page, "a+", "caat");
  await expect(page.getByText(/matched \(1\)/).first()).toBeVisible();
  expect(await page.locator("body").innerText()).not.toMatch(/Traceback|\[object/);
});

test("the engine choice persists after reload", async ({ page }) => {
  await page.goto("/regex");
  await engineSelect(page).selectOption("python-re");
  await page.reload();
  await expect(engineSelect(page)).toHaveValue("python-re");
  await engineSelect(page).selectOption({ label: /JavaScript/ });
  await page.reload();
  await expect(engineSelect(page).locator("option:checked")).toContainText("JavaScript");
});
