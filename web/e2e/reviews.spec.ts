import { expect, test } from "@playwright/test";
import { invitedPage, ownerPage } from "./helpers";

test.use({ baseURL: process.env.E2E_AUTH_URL });

test("review request on a rule: unread badge + toast, own approval blocked, stale decision 409, approve", async ({ browser, baseURL }) => {
  const owner = await ownerPage(browser, baseURL!);
  const alice = await invitedPage(browser, owner.ctx, baseURL!, "alice@example.com", "Alice Author", "editor");
  const bob = await invitedPage(browser, owner.ctx, baseURL!, "bob@example.com", "Bob Reviewer", "editor");
  const A = alice.page;
  const B = bob.page;

  // B is already looking at the app (any page) when A requests the review: unread badge + toast (U10).
  await B.goto("/rules");
  await expect(B.getByRole("link", { name: /My reviews/ })).toBeVisible();
  await expect(B.getByLabel(/reviews? waiting|unread/i)).toHaveCount(0);

  // A requests Bob's review of the rule in the Editor (reviews of scratch drafts are refused: 422).
  await A.goto("/editor/windows/powershell_encoded.yml");
  await expect(A.locator(".cm-content").first()).toContainText("PowerShell with an encoded command");
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

  // B's context: the badge next to "My reviews" and a toast appear on the next poll (forced here by a visibility change).
  await B.evaluate(() => document.dispatchEvent(new Event("visibilitychange", { bubbles: true })));
  const badge = B.getByRole("link", { name: /My reviews/ }).getByLabel(/1 /);
  await expect(badge).toBeVisible();
  await expect(B.getByRole("status").getByText(/New review: .* from Alice Author/)).toBeVisible();
  // Opening the review marks it read: the badge goes away.
  await B.goto("/reviews");
  await expect(B.getByText("please check the filter")).toBeVisible();
  await B.getByRole("link", { name: /PowerShell with an encoded command/ }).first().click();
  await expect(B).toHaveURL(/\/reviews\/[^/]+$/);
  await expect(B.getByRole("link", { name: /My reviews/ }).getByLabel(/\d/)).toHaveCount(0);
  const counts = await (await bob.ctx.request.get(`${baseURL}/api/reviews/counts`)).json();
  expect(counts.unread).toBe(0);

  // Stale decision: B has the review open, A changes the rule file meanwhile, B's Approve is a 409.
  await expect(B.getByRole("button", { name: "Approve" })).toBeVisible();
  const ruleId = review.target.ref;
  const cur = await (await alice.ctx.request.get(`${baseURL}/api/rules/${ruleId}`)).json();
  const put = await alice.ctx.request.put(`${baseURL}/api/rules/${ruleId}`, { data: { rule: cur.text + "\n# changed after the request\n", sha: cur.sha } });
  expect(put.ok(), await put.text()).toBeTruthy();
  await B.getByRole("button", { name: "Approve" }).click();
  await expect(B.getByText(/Could not apply|changed/)).toBeVisible();

  // Fresh state shows the stale warning; A asks again; B approves.
  await B.reload();
  await expect(B.getByText("The target changed after this review was requested.")).toBeVisible();
  await A.reload();
  await A.getByRole("tab", { name: "Review" }).click();
  await A.getByRole("button", { name: "Request again" }).click();
  await expect(A.getByRole("button", { name: "Request again" })).toHaveCount(0);
  await B.reload();
  const decided = B.waitForResponse((r) => r.url().includes("/decision"));
  await B.getByRole("button", { name: "Approve" }).click();
  const dr = await decided;
  expect(dr.status(), await dr.text()).toBe(200);
  const after = await (await bob.ctx.request.get(`${baseURL}/api/reviews/${review.id}`)).json();
  expect(after.state).toBe("approved");
  await B.reload(); // see BRIEFING: the review page may not refresh itself after a decision
  await expect(B.getByText("Approved", { exact: true }).first()).toBeVisible();
  await A.reload();
  await A.getByRole("tab", { name: "Review" }).click();
  await expect(A.getByText("Approved", { exact: true })).toBeVisible();

  await Promise.all([owner.ctx.close(), alice.ctx.close(), bob.ctx.close()]);
});
