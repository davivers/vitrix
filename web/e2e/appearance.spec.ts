import { expect, test } from "@playwright/test";

test.use({ baseURL: process.env.E2E_LOCAL_URL });

test("dark theme and Portuguese persist across reload", async ({ page }) => {
  await page.goto("/settings");
  const html = page.locator("html");
  await page.getByRole("radio", { name: "Dark" }).click();
  await expect(html).toHaveAttribute("data-theme", "dark");

  await page.getByRole("radio", { name: "Português (Brasil)" }).click(); // reloads with ?lang=pt
  await expect(html).toHaveAttribute("lang", "pt-BR");

  // Persist: a plain load without ?lang= keeps both.
  await page.goto("/settings");
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(html).toHaveAttribute("data-theme", "dark");
  await expect(page.getByRole("radio", { name: "Escuro" })).toHaveAttribute("aria-checked", "true");
  await expect(page.getByRole("radio", { name: "Português (Brasil)" })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("radio", { name: "English" }).click();
  await expect(html).toHaveAttribute("lang", "en");
});
