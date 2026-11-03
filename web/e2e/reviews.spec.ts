import { expect, test } from "@playwright/test";
import { invitedPage, ownerPage } from "./helpers";

test.use({ baseURL: process.env.E2E_AUTH_URL });

test("review request on a draft: comments, own approval blocked, stale decision 409, approve", async ({ browser, baseURL }) => {
  const owner = await ownerPage(browser, baseURL!);
  const alice = await invitedPage(browser, owner.ctx, baseURL!, "alice@example.com", "Alice Author", "editor");
  const bob = await invitedPage(browser, owner.ctx, baseURL!, "bob@example.com", "Bob Reviewer", "editor");
  const A = alice.page;
  const B = bob.page;

  // A saves a draft and requests Bob's review in the Editor.
  await A.goto("/editor/windows/powershell_encoded.yml");
  await expect(A.locator(".cm-content").first()).toContainText("PowerShell with an encoded command");
  await A.locator(".cm-content").first().click();
  await A.keyboard.press("Control+Home");
  await A.keyboard.insertText("# review me");
  await A.keyboard.press("Enter");
  await A.getByRole("button", { name: "Save locally" }).click();
  await expect(A.getByText(/Saved locally at/)).toBeVisible();
  // Reviews on a draft are requested from the opened draft (the rule route would target the rule file).
  const saved = await (await alice.ctx.request.get(`${baseURL}/api/drafts`)).json();
  await A.goto(`/editor?draft=${saved.drafts[0].id}`);
  await expect(A.locator(".cm-content").first()).toContainText("# review me");
  await A.getByRole("tab", { name: "Review" }).click();
  await A.getByRole("combobox").filter({ hasText: "Pick a member" }).selectOption({ label: "Bob Reviewer (bob@example.com)" });
  await A.getByPlaceholder("Note for the reviewer (optional)").fill("please check the filter");
  await A.getByRole("button", { name: "Request review" }).click();
  await expect(A.getByText("Pending")).toBeVisible();
  // A cannot approve own request (no buttons; the API refuses too).
  await expect(A.getByRole("button", { name: "Approve" })).toHaveCount(0);
  const mine = await (await alice.ctx.request.get(`${baseURL}/api/reviews?scope=all&state=open`)).json();
  const review = mine.reviews[0];
  const own = await alice.ctx.request.post(`${baseURL}/api/reviews/${review.id}/decision`, { data: { decision: "approved", note: null, version: review.version } });
  expect(own.status()).toBeGreaterThanOrEqual(400);
  expect(own.status()).toBeLessThan(500);

  // B sees it in My reviews and the sidebar badge.
  await B.goto("/reviews");
  await expect(B.getByLabel(/1 reviews waiting/)).toBeVisible();
  await expect(B.getByText("please check the filter")).toBeVisible();

  // Comment thread: B comments on the draft, A sees it.
  await B.getByRole("link", { name: /PowerShell with an encoded command/ }).click();
  await B.getByRole("tab", { name: "Review" }).click();
  await B.getByPlaceholder("Add a comment").fill("what about the SCCM filter?");
  await B.getByRole("button", { name: "Comment", exact: true }).click();
  await expect(B.getByText("what about the SCCM filter?")).toBeVisible();
  await A.reload();
  await A.getByRole("tab", { name: "Review" }).click();
  await expect(A.getByText("what about the SCCM filter?")).toBeVisible();

  // Stale decision: B has the review page open, A changes the draft meanwhile, B's Approve is a 409.
  await B.goto("/reviews");
  await expect(B.getByRole("button", { name: "Approve" })).toBeVisible();
  const draftId = review.target.ref;
  const d = await (await alice.ctx.request.get(`${baseURL}/api/drafts/${draftId}`)).json();
  const put = await alice.ctx.request.put(`${baseURL}/api/drafts/${draftId}`, {
    data: { path: d.path, title: d.title, rule: d.rule + "\n# changed after the request\n", cases: d.cases, version: d.version },
  });
  expect(put.ok(), await put.text()).toBeTruthy();
  await B.getByRole("button", { name: "Approve" }).click();
  await expect(B.getByText(/Could not apply: the target or the review changed/)).toBeVisible();

  // Fresh state shows the stale warning; A asks again; B approves.
  await B.reload();
  await expect(B.getByText("The target changed after this review was requested.")).toBeVisible();
  await A.reload();
  await A.getByRole("tab", { name: "Review" }).click();
  await A.getByRole("button", { name: "Request again" }).click();
  await B.reload();
  await B.getByRole("button", { name: "Approve" }).click();
  await expect(B.getByText("Nothing waiting for your review.")).toBeVisible();
  await A.reload();
  await A.getByRole("tab", { name: "Review" }).click();
  await expect(A.getByText("Approved", { exact: true })).toBeVisible();

  await Promise.all([owner.ctx.close(), alice.ctx.close(), bob.ctx.close()]);
});
