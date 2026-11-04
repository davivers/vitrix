import { expect, test } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { sigmaRule } from "./helpers";

// Sprint 4 on the accounts-off server: local rule files, Test & Replay, exports, regex flavor, connections.
test.use({ baseURL: process.env.E2E_LOCAL_URL });

const NEW_PATH = "e2e/local_new.yml";

test("Save locally on a new rule writes rules/ and the list shows Local, also after reload; a stale sha is a 409 conflict", async ({ page, request, baseURL }) => {
  await page.goto("/editor");
  await page.getByRole("button", { name: "Save locally" }).click();
  await page.getByLabel("Rule file path inside rules/").fill(NEW_PATH);
  await page.getByRole("button", { name: "Save here" }).click();
  await expect(page).toHaveURL(/\/editor\/e2e\/local_new\.yml/);
  await expect(page.getByText("Local · not in a PR").first()).toBeVisible();

  // The rule is a real file with a sha, and the API flags it as local.
  const saved = await (await request.get(`${baseURL}/api/rules/${NEW_PATH}`)).json();
  expect(saved.sha).toBeTruthy();
  expect(saved.publication.state).toBe("local");

  // Rules list: badge, and it survives a reload.
  await page.goto("/rules");
  const row = page.getByRole("row").filter({ hasText: "e2e/local_new.yml" }).first();
  await expect(row.getByText("Local · not in a PR")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("row").filter({ hasText: "e2e/local_new.yml" }).first().getByText("Local · not in a PR")).toBeVisible();

  // 409: someone else changes the file through the API after the Editor loaded it.
  await page.goto(`/editor/${NEW_PATH}`);
  await expect(page.locator(".cm-content").first()).toContainText("What this rule detects");
  const put = await request.put(`${baseURL}/api/rules/${NEW_PATH}`, { data: { rule: saved.text + "\n# changed elsewhere\n", sha: saved.sha } });
  expect(put.ok(), await put.text()).toBeTruthy();
  await page.locator(".cm-content").first().click();
  await page.keyboard.press("Control+Home");
  await page.keyboard.insertText("# my edit");
  await page.getByRole("button", { name: "Save locally" }).click();
  await expect(page.getByRole("button", { name: "Reload from disk" })).toBeVisible();
  // The other change is on disk, ours was not written over it.
  const after = await (await request.get(`${baseURL}/api/rules/${NEW_PATH}`)).json();
  expect(after.text).toContain("# changed elsewhere");
  expect(after.text).not.toContain("# my edit");
});

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const caseYaml = (name: string, expect: string, image: string, cmd: string) => `  - name: ${name}\n    expect: ${expect}\n    event:\n      Image: '${image}'\n      CommandLine: '${cmd}'\n`;
const GOOD_CASES = "cases:\n" + caseYaml("Positive · encoded command", "match", PS, "powershell.exe -enc JABzAD0A") + caseYaml("Negative · notepad", "no_match", "C:\\Windows\\notepad.exe", "notepad.exe -enc");
const FAILING_CASES = GOOD_CASES + caseYaml("Positive · plain script wrongly expected to match", "match", PS, "powershell.exe -File backup.ps1");
const REPLAY_ID = "5a1b3c4d-0000-4000-8000-0000000000a1";
// Events with no expectation file, so the quality gate stays green while Compare changes the match count.
const EVENTS = [
  { Image: PS, CommandLine: "powershell.exe -enc AAAA" },
  { Image: PS, CommandLine: "powershell.exe -enc BBBB" },
  { Image: PS, CommandLine: "powershell.exe -File backup.ps1" },
  { Image: "C:\\Windows\\notepad.exe", CommandLine: "notepad.exe" },
]
  .map((e) => JSON.stringify(e))
  .join("\n");

test("Test & Replay: one table with cases and datasets; Compare with saved version shows before and added matches", async ({ page, request, baseURL }) => {
  mkdirSync(path.join(process.env.E2E_LOCAL_DIR!, "datasets"), { recursive: true });
  writeFileSync(path.join(process.env.E2E_LOCAL_DIR!, "datasets", "e2e_events.jsonl"), EVENTS + "\n", "utf8");
  const path_ = "e2e/replay_ok.yml";
  const created = await request.post(`${baseURL}/api/rules`, { data: { path: path_, rule: sigmaRule("E2E replay rule", REPLAY_ID), cases: GOOD_CASES } });
  expect(created.ok(), await created.text()).toBeTruthy();

  await page.goto(`/editor/${path_}`);
  await expect(page.locator(".cm-content").first()).toContainText("E2E replay rule");
  // The old Tests / Impact tabs are gone; Replay is Test & Replay.
  await expect(page.getByRole("tab", { name: "Impact" })).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "Tests", exact: true })).toHaveCount(0);
  await page.getByRole("tab", { name: "Test & Replay" }).click();

  const table = page.getByRole("table", { name: "Draft replay per dataset" });
  await expect(table).toBeVisible();
  // One table: both sections.
  await expect(table.getByRole("columnheader", { name: /Cases \(events with an expected result\)/ })).toBeVisible();
  await expect(table.getByRole("columnheader", { name: /Datasets/ })).toBeVisible();
  await expect(table.getByRole("row", { name: /Positive · encoded command/ })).toBeVisible();
  await expect(table.getByRole("row", { name: /e2e_events/ })).toContainText("2 / 4");

  // Compare with saved version: change the rule in the editor (drop the CommandLine filter): 3 matches now, 2 before.
  await page.getByLabel("Compare with saved version").check();
  const cm = page.locator(".cm-content").first();
  await cm.click();
  await page.keyboard.press("Control+A");
  await page.keyboard.insertText(sigmaRule("E2E replay rule", REPLAY_ID, { selection: "Image|endswith: '\powershell.exe'" }));
  const ds = page.getByRole("table", { name: "Draft replay per dataset" }).getByRole("row", { name: /e2e_events/ });
  await expect(ds).toContainText("3 / 4");
  await expect(ds).toContainText("before 2");
  await ds.getByRole("button", { name: /e2e_events/ }).click();
  await expect(page.getByText(/Now match:\s*#2/)).toBeVisible();
});

// Regression (was a frontend bug): the Replay panel must stay usable when the gate state is
// "fail" because of a failing case: the field-level diff must stay reachable.
test("Test & Replay: a failing case expands to the field-level diff", async ({ page, request, baseURL }) => {
  const path_ = "e2e/replay_fail.yml";
  const created = await request.post(`${baseURL}/api/rules`, { data: { path: path_, rule: sigmaRule("E2E failing case", "5a1b3c4d-0000-4000-8000-0000000000a4"), cases: FAILING_CASES } });
  expect(created.ok(), await created.text()).toBeTruthy();
  await page.goto(`/editor/${path_}`);
  await page.getByRole("tab", { name: "Test & Replay" }).click();
  const table = page.getByRole("table", { name: "Draft replay per dataset" });
  await expect(table).toBeVisible({ timeout: 8_000 });
  const failing = table.getByRole("row", { name: /plain script wrongly expected to match/ });
  await expect(failing).toContainText("Fail");
  await expect(failing).toContainText("selection");
  await expect(failing).toContainText("did not match");
  await expect(failing).toContainText("CommandLine");
  await expect(failing).toContainText("wants");
  await expect(failing).toContainText("has");
});

const NEG = "  - name: Negative · harmless\n    expect: no_match\n    event:\n      CommandLine: 'b'\n";
const SLOW_RULE = sigmaRule("E2E slow regex", "5a1b3c4d-0000-4000-8000-0000000000a2", { selection: "CommandLine|re: '^(a|aa)+$'" });
const SLOW_CASES = `cases:\n  - name: Positive · long run of a\n    expect: match\n    event:\n      CommandLine: '${"a".repeat(64)}!'\n${NEG}`;
const UNSUPPORTED_RULE = sigmaRule("E2E unsupported", "5a1b3c4d-0000-4000-8000-0000000000a3", { selection: "CommandLine|expand: '%cmd%'" });
const UNSUPPORTED_CASES = `cases:\n  - name: Positive · anything\n    expect: match\n    event:\n      CommandLine: 'x'\n${NEG}`;

// Regression (was a telemetry bug): a regex timeout in replay must come back as code "regex-timeout" with a regex hint,
// not "unsupported" with the generic hint.
for (const [name, rule, cases, code, expectFail] of [
  ["a regex timeout", SLOW_RULE, SLOW_CASES, "regex-timeout", false],
  ["an unsupported feature", UNSUPPORTED_RULE, UNSUPPORTED_CASES, "unsupported", false],
] as const) {
  test(`Replay API: ${name} is a structured error with a hint`, async ({ request, baseURL }) => {
    test.fail(expectFail, "expected failure");
    const r = await request.post(`${baseURL}/api/replay/draft`, { data: { rule, cases } });
    expect(r.ok(), await r.text()).toBeTruthy();
    const body = await r.json();
    const err = [...body.cases.map((c: { error: unknown }) => c.error), ...body.datasets.map((d: { error: unknown }) => d.error)].find(Boolean) as { code: string; message: string; hint: string };
    expect(err, JSON.stringify(body.cases).slice(0, 900)).toBeTruthy();
    expect(err.code, JSON.stringify(err)).toBe(code);
    expect(err.hint.length).toBeGreaterThan(5);
    expect(err.message).not.toMatch(/Traceback|Error\(|Exception/);
  });
}

// Regression (was a frontend bug): a replay error makes the gate "fail"; the Replay panel must stay usable so
// the readable error card is reachable from the Editor.
for (const [name, rule, cases, file, title] of [
  ["a regex that times out", SLOW_RULE, SLOW_CASES, "e2e/replay_slow.yml", /regular expression/i],
  ["a feature replay cannot run", UNSUPPORTED_RULE, UNSUPPORTED_CASES, "e2e/replay_unsupported.yml", /cannot run|unsupported/i],
] as const) {
  test(`Test & Replay: ${name} renders as a readable error card with a hint`, async ({ page, request, baseURL }) => {
    const created = await request.post(`${baseURL}/api/rules`, { data: { path: file, rule, cases } });
    expect(created.ok(), await created.text()).toBeTruthy();
    await page.goto(`/editor/${file}`);
    await page.getByRole("tab", { name: "Test & Replay" }).click();
    const alert = page.getByRole("alert").filter({ hasText: title }).first();
    await expect(alert).toBeVisible({ timeout: 8_000 });
    await expect(alert).toContainText("Hint:");
    await expect(alert).not.toContainText(/Traceback|TimeoutError|UnsupportedError|Exception/);
  });
}

test("Exports: Executive and Operational offer Markdown and CSV downloads; /reports redirects", async ({ page }) => {
  await page.goto("/reports");
  await expect(page).toHaveURL(/\/executive$/);
  await expect(page.getByRole("link", { name: "Reports" })).toHaveCount(0);

  for (const route of ["/executive", "/dashboard"]) {
    await page.goto(route);
    await page.getByRole("button", { name: "Export" }).click();
    await expect(page.getByRole("menuitem", { name: "Print / Save as PDF" })).toBeVisible();
    const md = page.waitForEvent("download");
    await page.getByRole("menuitem", { name: "Markdown (.md)" }).click();
    expect((await md).suggestedFilename()).toMatch(/\.md$/);
    await page.getByRole("button", { name: "Export" }).click();
    const csvItem = page.locator("[role=menuitem]:not([disabled])", { hasText: /CSV: / }).first();
    await expect(csvItem).toBeVisible();
    const csv = page.waitForEvent("download");
    await csvItem.click();
    expect((await csv).suggestedFilename()).toMatch(/\.csv$/);
  }
});

test("Connections lists the supported query languages and no SIEM deploy blocks", async ({ page }) => {
  await page.goto("/connections");
  await expect(page.getByRole("heading", { name: "Supported query languages" })).toBeVisible();
  await expect(page.getByText("Rules convert locally. Nothing is sent to a SIEM.")).toBeVisible();
  await expect(page.getByRole("table").first()).toContainText(/Splunk/);
  await expect(page.getByRole("columnheader", { name: "Language" })).toBeVisible();
  for (const siem of [/Deploy to/i, /Connect (your )?SIEM/i, /SIEM credentials/i]) await expect(page.getByText(siem)).toHaveCount(0);
});
