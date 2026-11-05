import { defineConfig } from "@playwright/test";
const browser =
  process.env.LOCKLARK_TEST_BROWSER === "firefox" ? "firefox" : "chromium";
export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  use: {
    baseURL: "http://127.0.0.1:3417",
    trace: "off",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "node tests/run-stack.mjs",
    url: "http://127.0.0.1:3417",
    timeout: 120_000,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
  },
  projects: [{ name: browser, use: { browserName: browser } }],
});
