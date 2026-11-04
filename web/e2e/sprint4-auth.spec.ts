import { expect, test } from "@playwright/test";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { git, invitedPage, ownerPage, pushToBare, sigmaRule } from "./helpers";

// Sprint 4 on the accounts-on server, whose repo is a clone of a local bare "GitHub" repo (global-setup).
test.use({ baseURL: process.env.E2E_AUTH_URL });
test.describe.configure({ mode: "serial" });

test("scratch drafts are private to their author and are gone after sign-out / sign-in", async ({ browser, baseURL }) => {
  const owner = await ownerPage(browser, baseURL!);
  const dana = await invitedPage(browser, owner.ctx, baseURL!, "dana@example.com", "Dana Draft", "editor");
  const ed = await invitedPage(browser, owner.ctx, baseURL!, "ed2@example.com", "Ed Other", "editor");
  const D = dana.page;

  await D.goto("/editor/windows/powershell_encoded.yml");
  await expect(D.locator(".cm-content").first()).toContainText("PowerShell with an encoded command");
  await D.locator(".cm-content").first().click();
  await D.keyboard.press("Control+Home");
  await D.keyboard.insertText("# dana scratch");
  await D.keyboard.press("Enter");
  await D.getByRole("button", { name: "Keep as scratch draft" }).click();
  await expect(D.getByText(/Saved locally at/)).toBeVisible();

  const mine = await (await dana.ctx.request.get(`${baseURL}/api/drafts`)).json();
  expect(mine.drafts).toHaveLength(1);
  const id = mine.drafts[0].id;

  // Another user (and the owner) neither lists nor reads it.
  for (const other of [ed.ctx, owner.ctx]) {
    const list = await (await other.request.get(`${baseURL}/api/drafts`)).json();
    expect(list.drafts.map((d: { id: string }) => d.id)).not.toContain(id);
    expect((await other.request.get(`${baseURL}/api/drafts/${id}`)).status()).toBe(404);
  }

  // Sign out, sign in again: the scratch draft is cleared.
  await D.getByRole("button", { name: /Account menu/ }).click();
  await D.getByRole("menuitem", { name: "Sign out" }).or(D.getByRole("button", { name: "Sign out" })).first().click();
  await expect(D.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await D.getByLabel("Email").fill("dana@example.com");
  await D.getByLabel("Password").fill("correct-horse-battery");
  await D.getByRole("button", { name: "Sign in" }).last().click();
  await expect(D.getByRole("button", { name: /Account menu/ })).toBeVisible();
  const again = await (await D.request.get(`${baseURL}/api/drafts`)).json();
  expect(again.drafts).toHaveLength(0);
  await D.goto("/editor/windows/powershell_encoded.yml");
  await expect(D.getByRole("button", { name: /^Drafts \(0\)/ })).toBeVisible();

  await Promise.all([owner.ctx.close(), dana.ctx.close(), ed.ctx.close()]);
});

test("sync: a rule pushed to GitHub appears after a reload; a conflicting untracked local file is reported, never overwritten", async ({ browser, baseURL }) => {
  test.setTimeout(150_000);
  const owner = await ownerPage(browser, baseURL!);
  const page = owner.page;
  const dir = process.env.E2E_AUTH_DIR!;
  // Earlier specs wrote tracked example rules (review edits); start the sync scenario from a clean tracked tree.
  git(dir, "checkout", "--", "rules", "cases");

  await page.goto("/rules");
  await expect(page.getByTestId("sync-chip")).toContainText("Synced with GitHub");
  expect(((await (await owner.ctx.request.get(`${baseURL}/api/rules`)).json()) as { id: string }[]).map((r) => r.id)).not.toContain("e2e/from_github.yml");

  // A teammate merges a new rule on GitHub.
  pushToBare({ "rules/e2e/from_github.yml": sigmaRule("Rule from GitHub", "5a1b3c4d-0000-4000-8000-0000000000b1") }, "Add rule from GitHub");

  // Reload: the app fetches on load (throttled; "Sync now" is allowed again after 5 s) and fast-forwards.
  await expect
    .poll(
      async () => {
        await page.reload();
        const chip = page.getByTestId("sync-chip");
        await expect(chip).toBeVisible();
        await chip.click();
        const now = page.getByRole("button", { name: "Sync now" });
        if (await now.isEnabled()) await now.click();
        await page.waitForTimeout(2000);
        const list = await (await owner.ctx.request.get(`${baseURL}/api/rules`)).json();
        return (list as { id: string }[]).some((r: { id: string }) => r.id === "e2e/from_github.yml");
      },
      { timeout: 50_000, intervals: [3_000] },
    )
    .toBe(true);
  // ... and the Rules screen shows it (flagged as published: it came from origin, no "Local" badge).
  await page.goto("/rules");
  const row = page.getByRole("row").filter({ hasText: "e2e/from_github.yml" });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row.getByText("Local · not in a PR")).toHaveCount(0);
  const pulled = readFileSync(path.join(dir, "rules/e2e/from_github.yml"), "utf8");
  expect(pulled).toContain("Rule from GitHub");

  // Conflict: an untracked local file differs from the file GitHub now has at the same path.
  const clash = path.join(dir, "rules/e2e/clash.yml");
  mkdirSync(path.dirname(clash), { recursive: true });
  const mine = sigmaRule("My local clash", "5a1b3c4d-0000-4000-8000-0000000000b2");
  writeFileSync(clash, mine, "utf8");
  pushToBare({ "rules/e2e/clash.yml": sigmaRule("Their clash", "5a1b3c4d-0000-4000-8000-0000000000b3") }, "Add clashing rule");
  await expect
    .poll(
      async () => {
        const r = await owner.ctx.request.post(`${baseURL}/api/sync`, { data: { force: true } });
        if (!r.ok()) return `HTTP ${r.status()}`;
        await page.waitForTimeout(1500);
        const s = await (await owner.ctx.request.get(`${baseURL}/api/sync`)).json();
        return s.conflicts.map((c: { path: string }) => c.path).join(",");
      },
      { timeout: 60_000, intervals: [6_000] },
    )
    .toContain("rules/e2e/clash.yml");
  expect(readFileSync(clash, "utf8")).toBe(mine); // never overwritten
  await page.reload();
  await expect(page.getByTestId("sync-chip")).toContainText(/1 conflict/);
  await page.getByTestId("sync-chip").click();
  await expect(page.getByRole("dialog", { name: "GitHub sync" })).toContainText("rules/e2e/clash.yml");

  await owner.ctx.close();
});
