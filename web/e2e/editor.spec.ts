import { expect, test } from "@playwright/test";
import { appendLine } from "./helpers";

test.use({ baseURL: process.env.E2E_LOCAL_URL });
test.describe.configure({ mode: "serial" });

const RULE = "/editor/windows/powershell_encoded.yml";

test("scratch drafts: sheet, 409 conflict, test & replay and gate", async ({ page, request, baseURL }) => {
  await page.goto(RULE);
  await expect(page.locator(".cm-content").first()).toContainText("PowerShell with an encoded command");

  // Quality gate tab shows the verdict.
  await page.getByRole("tab", { name: "Quality gate" }).click();
  await expect(page.getByText("Approved", { exact: true }).first()).toBeVisible();

  // Edit with the keyboard and save locally.
  await appendLine(page, "# e2e marker one");
  await expect(page.getByText("Unsaved changes")).toBeVisible();
  await page.getByRole("button", { name: "Keep as scratch draft" }).click();
  await expect(page.getByText(/Saved locally at/)).toBeVisible();

  // Drafts sheet lists it.
  await page.getByRole("button", { name: /^Drafts \(1\)/ }).click();
  const sheet = page.getByRole("dialog", { name: "Local drafts" });
  await expect(sheet).toBeVisible();
  await expect(sheet.getByText("PowerShell with an encoded command")).toBeVisible();
  await expect(sheet.getByText("windows/powershell_encoded.yml")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(sheet).toBeHidden();

  // Reopen it from a fresh page load.
  const list = await (await request.get(`${baseURL}/api/drafts`)).json();
  expect(list.drafts).toHaveLength(1);
  const draft = list.drafts[0];
  const stored = await (await request.get(`${baseURL}/api/drafts/${draft.id}`)).json();
  expect(stored.rule).toContain("# e2e marker one");
  await page.goto(`/editor?draft=${draft.id}`);
  await expect(page.locator(".cm-content").first()).toContainText("# e2e marker one");

  // 409: someone else changes the draft through the API, then we save from the UI.
  const full = await (await request.get(`${baseURL}/api/drafts/${draft.id}`)).json();
  const put = await request.put(`${baseURL}/api/drafts/${draft.id}`, {
    data: { path: full.path, title: full.title, rule: full.rule + "\n# changed elsewhere\n", cases: full.cases, version: full.version },
  });
  expect(put.ok(), await put.text()).toBeTruthy();
  await appendLine(page, "# e2e marker two");
  await page.getByRole("button", { name: "Keep as scratch draft" }).click();
  await expect(page.getByText("Someone saved a newer version.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reload draft" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Overwrite as new" })).toBeVisible();

  // Reload draft brings the other change in.
  await page.getByRole("button", { name: "Reload draft" }).click();
  await expect(page.getByText("Someone saved a newer version.")).toBeHidden();
  await expect(page.locator(".cm-content").first()).toContainText("# e2e marker one");
  await expect(page.locator(".cm-content").first()).not.toContainText("# e2e marker two");
  const latest = await (await request.get(`${baseURL}/api/drafts/${draft.id}`)).json();
  expect(latest.rule).toContain("# changed elsewhere");

  // Replay tab -> run -> results table.
  await page.getByRole("tab", { name: "Test & Replay" }).click();
  const table = page.getByRole("table", { name: "Draft replay per dataset" });
  await expect(table).toBeVisible(); // run-on-edit is on by default
  const row = table.getByRole("row", { name: /windows_attack_simulation/ });
  await expect(row).toBeVisible();
  await expect(row.getByRole("cell").nth(3)).toContainText("2 /"); // matches / events
  await row.getByRole("button", { name: /windows_attack_simulation/ }).click();
  await expect(page.getByText("Matched event")).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: /powershell/i }).first()).toBeVisible();
});

test("save as new after a conflict", async ({ page, request, baseURL }) => {
  const list = await (await request.get(`${baseURL}/api/drafts`)).json();
  const d = await (await request.get(`${baseURL}/api/drafts/${list.drafts[0].id}`)).json();
  await page.goto(`/editor?draft=${d.id}`);
  await expect(page.locator(".cm-content").first()).toContainText("PowerShell");
  await request.put(`${baseURL}/api/drafts/${d.id}`, { data: { path: d.path, title: d.title, rule: d.rule + "\n# bump\n", cases: d.cases, version: d.version } });
  await appendLine(page, "# e2e marker three");
  await page.getByRole("button", { name: "Keep as scratch draft" }).click();
  await page.getByRole("button", { name: "Overwrite as new" }).click();
  await page.getByRole("button", { name: "Keep as scratch draft" }).click();
  await expect(page.getByText(/Saved locally at/)).toBeVisible();
  await expect.poll(async () => (await (await request.get(`${baseURL}/api/drafts`)).json()).drafts.length).toBe(2);
});
