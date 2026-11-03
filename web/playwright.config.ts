import { defineConfig } from "@playwright/test";

// Real-browser E2E. Uses the installed Microsoft Edge (no browser download). Run: npm run e2e
// Requires a built UI (npm run build) and the Python venv at ../venv (see e2e/global-setup.ts).
// Artifacts (failure screenshots, traces, HTML report) stay out of git: see web/.gitignore.
export default defineConfig({
  testDir: "./e2e",
  outputDir: "test-results",
  globalSetup: "./e2e/global-setup.ts",
  workers: 1, // the auth suite is stateful (owner -> invite -> roles)
  fullyParallel: false,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    channel: "msedge",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "off",
  },
});
