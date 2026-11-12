import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = "https://security-assessment-alpha.buttercoder-dev.workers.dev";
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
const page = await context.newPage();
const pageErrors = [];
page.on("pageerror", error => pageErrors.push(error.message));
page.on("console", message => {
  if (message.type() === "error") pageErrors.push(message.text());
});

try {
  const response = await page.goto(base, { waitUntil: "networkidle", timeout: 30000 });
  assert.equal(response?.status(), 200, "dashboard must load");
  await page.waitForFunction(
    () => document.querySelector("#status")?.textContent.trim() === "Private workspace",
    null,
    { timeout: 15000 }
  );
  assert.equal(await page.locator("#scan-notice").isHidden(), true,
    "ready scanner must not show the paused notice");
  assert.match(await page.locator("#form-hint").innerText(),
    /Passive-only assessment: one HTTPS GET/);

  for (const width of [320, 375, 768, 1120]) {
    await page.setViewportSize({ width, height: 812 });
    await page.waitForTimeout(100);
    const overflow = await page.evaluate(() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth
    }));
    assert.ok(overflow.document <= overflow.viewport,
      `horizontal overflow at ${width}px: ${JSON.stringify(overflow)}`);
  }

  await page.locator("#url").fill("https://example.com");
  await page.locator("#add").click();
  const target = page.locator("#targets .target").filter({ hasText: "example.com" });
  await target.waitFor({ state: "visible", timeout: 15000 });
  const proofValues = await target.locator(".proof-value").allTextContents();
  assert.ok(proofValues.includes("_secops-verification.example.com"),
    "ownership TXT record name must be displayed");
  assert.ok(proofValues.some(value => value.trim().length >= 32),
    "ownership TXT token must be displayed");
  const actions = await target.locator("button").allTextContents();
  assert.ok(actions.some(value => value.includes("Verify DNS record")));
  assert.ok(!actions.some(value => value.includes("Run assessment")),
    "unverified target must not expose the assessment action");

  page.once("dialog", dialog => dialog.accept());
  await target.getByRole("button", { name: "Remove" }).click();
  await target.waitFor({ state: "detached", timeout: 15000 });
  assert.equal(await page.locator("#targets .target-host").count(), 0,
    "temporary target must be removed from the rendered workspace");
  assert.deepEqual(pageErrors, [], "browser must not report JavaScript or console errors");

  console.log(JSON.stringify({
    ok: true,
    anonymous_workspace: "passed",
    readiness_notice: "hidden",
    responsive_widths: [320, 375, 768, 1120],
    dns_txt_challenge: "displayed",
    unverified_scan_action: "correctly hidden",
    target_removal: "passed",
    browser_errors: pageErrors.length
  }, null, 2));
} finally {
  await context.close();
  await browser.close();
}
