import { expect, test, type APIRequestContext } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";

// Sprint 5 on the accounts-off server: inline KQL fixes, mappings.yml, final-language selector, Rules "not in Git yet".
test.use({ baseURL: process.env.E2E_LOCAL_URL });

const rule = (title: string, id: string, product: string, service: string, vitrix = "") => `title: ${title}
id: ${id}
status: experimental
description: E2E rule ${title}
author: e2e
date: 2026-11-04
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: ${product}
  service: ${service}
detection:
  selection:
    action: 'test'
  condition: selection
falsepositives:
  - none
level: medium
${vitrix}`;
const CASES = "cases:\n  - name: Positive · match\n    expect: match\n    event:\n      action: 'test'\n  - name: Negative · other\n    expect: no_match\n    event:\n      action: 'other'\n";

async function create(request: APIRequestContext, baseURL: string, file: string, text: string) {
  const r = await request.post(`${baseURL}/api/rules`, { data: { path: file, rule: text, cases: CASES } });
  expect(r.ok(), await r.text()).toBeTruthy();
}

const KQL_FINAL = "vitrix:\n  target: kql\n";

test("KQL table fix inline: this rule only writes vitrix.kql_table into the YAML and the KQL query renders", async ({ page, request, baseURL }) => {
  await create(request, baseURL!, "e2e5/bb_one.yml", rule("E2E bitbucket one", "5a1b3c4d-0000-4000-8000-0000000000c1", "bitbucket", "audit", KQL_FINAL));
  await page.goto("/editor/e2e5/bb_one.yml");
  await expect(page.locator(".cm-content").first()).toContainText("E2E bitbucket one");
  // (d) the header counts the final-language failure as an error.
  await expect(page.getByText("1 error", { exact: false }).first()).toBeVisible();

  await page.getByRole("tab", { name: "Queries" }).click();
  const form = page.getByRole("form", { name: "Fix: choose the KQL table" });
  await expect(form).toBeVisible();
  await expect(form.getByLabel("Table name")).toHaveValue("BitbucketAudit_CL");
  await expect(form.getByLabel("This rule only")).toBeChecked();
  await form.getByRole("button", { name: "Apply" }).click();

  // The YAML in the editor got the key (unsaved), the form is gone and the KQL query shows the table.
  await expect(page.locator(".cm-content").first()).toContainText("kql_table: BitbucketAudit_CL");
  await expect(form).toHaveCount(0);
  await expect(page.getByText("BitbucketAudit_CL").first()).toBeVisible();
  await expect(page.getByText("1 error", { exact: false })).toHaveCount(0);
});

test("KQL table fix for all rules writes mappings.yml, survives reload and is listed in Settings", async ({ page, request, baseURL }) => {
  await create(request, baseURL!, "e2e5/bb_two.yml", rule("E2E bitbucket two", "5a1b3c4d-0000-4000-8000-0000000000c2", "bitbucket", "audit", KQL_FINAL));
  await page.goto("/editor/e2e5/bb_two.yml");
  await page.getByRole("tab", { name: "Queries" }).click();
  const form = page.getByRole("form", { name: "Fix: choose the KQL table" });
  await form.getByLabel("All bitbucket/audit rules").check();
  await form.getByRole("button", { name: "Apply" }).click();
  await expect(form).toHaveCount(0);

  const maps = await (await request.get(`${baseURL}/api/mappings`)).json();
  expect(maps.exists).toBe(true);
  expect(maps.kql.tables["bitbucket/audit"]).toBe("BitbucketAudit_CL");
  expect(readFileSync(path.join(process.env.E2E_LOCAL_DIR!, "mappings.yml"), "utf8")).toContain("BitbucketAudit_CL");
  // The rule YAML itself was not touched (the mapping is repo-wide).
  await expect(page.locator(".cm-content").first()).not.toContainText("kql_table");

  await page.reload();
  await page.getByRole("tab", { name: "Queries" }).click();
  await expect(page.getByRole("form", { name: "Fix: choose the KQL table" })).toHaveCount(0);
  await expect(page.getByText("BitbucketAudit_CL").first()).toBeVisible();

  await page.goto("/settings");
  await page.getByRole("link", { name: "Query mappings" }).or(page.getByRole("button", { name: "Query mappings" })).first().click();
  await expect(page.getByText("bitbucket/audit").first()).toBeVisible();
  await expect(page.getByLabel("Table for bitbucket/audit")).toHaveValue("BitbucketAudit_CL");
});

test("KQL table fix refuses an injection attempt with a message and writes nothing", async ({ page, request, baseURL }) => {
  await create(request, baseURL!, "e2e5/gh_one.yml", rule("E2E github audit", "5a1b3c4d-0000-4000-8000-0000000000c3", "github", "audit", KQL_FINAL));
  const before = await (await request.get(`${baseURL}/api/mappings`)).json();
  await page.goto("/editor/e2e5/gh_one.yml");
  await page.getByRole("tab", { name: "Queries" }).click();
  const form = page.getByRole("form", { name: "Fix: choose the KQL table" });
  await expect(form).toBeVisible();
  await form.getByLabel("All github/audit rules").check();
  await form.getByLabel("Table name").fill("Bad|Table");
  await form.getByRole("button", { name: "Apply" }).click();
  await expect(form.getByRole("alert").or(form.getByText(/invalid|not allowed|identifier|letters/i)).first()).toBeVisible();
  const after = await (await request.get(`${baseURL}/api/mappings`)).json();
  expect(after.kql.tables["github/audit"]).toBeUndefined();
  expect(after.sha).toBe(before.sha);

  // Same attempt at rule scope: the YAML gets the value but the lint/conversion refuses it, nothing reaches a query.
  await form.getByLabel("This rule only").check();
  await form.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText(/Bad\|Table\s*\|/)).toHaveCount(0);
});

test("Final language: Sigma (no conversion) passes conversion and shows the Sigma YAML as final", async ({ page, request, baseURL }) => {
  await create(request, baseURL!, "fl5/a.yml", rule("E2E final one", "5a1b3c4d-0000-4000-8000-0000000000d1", "okta", "system", KQL_FINAL));
  await create(request, baseURL!, "fl5/b.yml", rule("E2E final two", "5a1b3c4d-0000-4000-8000-0000000000d2", "okta", "system", KQL_FINAL));
  await page.goto("/editor/fl5/a.yml");
  await expect(page.getByText("1 error", { exact: false }).first()).toBeVisible();

  await page.getByRole("button", { name: /^final language:/ }).click();
  await page.getByRole("menuitemradio", { name: "Sigma (no conversion)" }).click();
  await expect(page.locator(".cm-content").first()).toContainText("target: sigma");
  await expect(page.getByText("1 error", { exact: false })).toHaveCount(0);

  await page.getByRole("tab", { name: "Queries" }).click();
  // The final artifact is the Sigma rule itself.
  await expect(page.getByText("Sigma (no conversion)").first()).toBeVisible();
  await expect(page.getByText("title: E2E final one").first()).toBeVisible();
  const v = await (await request.post(`${baseURL}/api/validate`, { data: { rule: rule("E2E final one", "5a1b3c4d-0000-4000-8000-0000000000d1", "okta", "system", "vitrix:\n  target: sigma\n") } })).json();
  expect(v.final_language.targets).toEqual(["sigma"]);
  expect(v.counts.errors).toBe(0);
});

test("Final language: use for all rules in a folder, shown in Settings and inherited; Use default removes vitrix.target", async ({ page, request, baseURL }) => {
  // b.yml has no own target: it inherits the folder default once it is set from a.yml.
  await create(request, baseURL!, "fl6/a.yml", rule("E2E folder one", "5a1b3c4d-0000-4000-8000-0000000000e1", "windows", "sysmon", KQL_FINAL));
  await create(request, baseURL!, "fl6/b.yml", rule("E2E folder two", "5a1b3c4d-0000-4000-8000-0000000000e2", "windows", "sysmon"));
  await page.goto("/editor/fl6/a.yml");
  await page.getByRole("button", { name: /^final language:/ }).click();
  await expect(page.getByText("Use for all rules in fl6/", { exact: false })).toBeVisible(); // group heading
  await page.getByRole("menu").getByRole("menuitem", { name: "Sigma (no conversion)" }).last().click();
  await expect(page.getByText("Saved as the default for fl6/")).toBeVisible();

  const maps = await (await request.get(`${baseURL}/api/mappings`)).json();
  expect(Object.keys(maps.final_language.folders).some((k) => k.startsWith("fl6"))).toBe(true);
  const b = await (await request.get(`${baseURL}/api/rules/fl6/b.yml`)).json();
  expect(b.final_language.source).toBe("folder");

  await page.goto("/settings");
  await page.getByRole("link", { name: "Final language" }).or(page.getByRole("button", { name: "Final language" })).first().click();
  await expect(page.getByText(/fl6\//).first()).toBeVisible();

  // The other rule reports the source in its own Editor.
  await page.goto("/editor/fl6/b.yml");
  await expect(page.getByText("folder default").first()).toBeVisible();

  // "Use default" removes the key from the YAML of a.yml.
  await page.goto("/editor/fl6/a.yml");
  await expect(page.locator(".cm-content").first()).toContainText("target: kql");
  await page.getByRole("button", { name: /^final language:/ }).click();
  await page.getByRole("menuitemradio", { name: "Use default" }).click();
  await expect(page.locator(".cm-content").first()).not.toContainText("target: kql");
});

test("Rules: local badge, Not in Git yet filter, banner and row Publish opens the publish dialog (GitHub stubbed)", async ({ page, request, baseURL }) => {
  await create(request, baseURL!, "e2e5/pub_one.yml", rule("E2E publish me", "5a1b3c4d-0000-4000-8000-0000000000f1", "windows", "sysmon"));
  await page.route("**/api/github", (r) => r.fulfill({ json: { configured: true, source: "git remote", repo: "e2e/repo", base: "main", workflow: "vitrix.yml", token: true, token_source: "GITHUB_TOKEN" } }));
  await page.route("**/api/ci/rules", (r) =>
    r.fulfill({ status: 201, json: { branch: "vitrix/e2e", commit: "abc1234", base: "main", base_commit: "def5678", url: "https://example.invalid/b", title: "E2E publish me", files: ["rules/e2e5/pub_one.yml", "mappings.yml"], is_new: false, mappings_included: true } }),
  );
  await page.route("**/api/ci/status**", (r) => r.fulfill({ json: { state: "pending", runs: [], commit: "abc1234" } }));

  await page.goto("/rules");
  await expect(page.getByText(/rules? (is|are) saved only locally/).first()).toBeVisible();
  const row = page.locator("tbody tr", { hasText: "E2E publish me" });
  await expect(row.getByText("Local · not in a PR")).toBeVisible();
  await page.getByRole("button", { name: /Not in Git yet/ }).click();
  await expect(row).toBeVisible();
  // (the example rules are committed but there is no remote here, so they count as "not in Git yet" too: see BRIEFING)

  await page.getByRole("button", { name: "Publish E2E publish me" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Validate in CI" }).click();
  // mappings.yml changed locally (earlier tests), so the dialog says it travels with the rule.
  await expect(dialog.getByText("mappings.yml is included in this pull request because it changed locally.")).toBeVisible();
});

test("Rules: a repository without Git shows 'Local · Git not connected'", async ({ page, request }) => {
  const url = process.env.E2E_NOGIT_URL!;
  const r = await request.post(`${url}/api/rules`, { data: { path: "e2e5/nogit.yml", rule: rule("E2E no git", "5a1b3c4d-0000-4000-8000-0000000000f2", "windows", "sysmon"), cases: CASES } });
  expect(r.ok(), await r.text()).toBeTruthy();
  await page.goto(`${url}/rules`);
  const row = page.locator("tbody tr", { hasText: "E2E no git" });
  await expect(row.getByText("Local · Git not connected")).toBeVisible();
  await page.goto(`${url}/editor/e2e5/nogit.yml`);
  await expect(page.getByText("Local · Git not connected").first()).toBeVisible();
});
