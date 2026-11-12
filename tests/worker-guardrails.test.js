import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../worker.js", import.meta.url), "utf8");

test("scan route requires both the release flag and the dedicated EGRESS binding", () => {
  assert.match(source, /if\(!e\.EGRESS\|\|e\.SCAN_EGRESS_READY!=="enabled"\)return json\(\{error:/);
  assert.match(source, /e\.EGRESS\.fetch\(t\.url/);
  assert.doesNotMatch(source, /const res=await fetch\(t\.url/);
});

test("ownership proof is DNS TXT only", () => {
  assert.match(source, /_secops-verification\."\+t\.hostname/);
  assert.doesNotMatch(source, /fetch\(t\.url\+"\/.well-known/);
});

test("non-GET API requests require exact same-origin Origin", () => {
  assert.match(source, /r\.method!==\"GET\"&&r\.headers\.get\(\"origin\"\)!==u\.origin/);
});

test("scan requests do not follow redirects", () => {
  assert.match(source, /redirect:\"manual\"/);
});

test("cookie has secure browser protections", () => {
  assert.match(source, /; Secure; HttpOnly; SameSite=Strict/);
});

test("UI hides the paused notice when the health endpoint reports scanner readiness", () => {
  assert.match(source, /id="scan-notice"/);
  assert.match(source, /\$\("#scan-notice"\)\.hidden=scannerReady/);
});

test("inline UI assets use per-response CSP nonces", () => {
  assert.match(source, /<style nonce="__CSP_NONCE__">/);
  assert.match(source, /<script nonce="__CSP_NONCE__">/);
  assert.doesNotMatch(source, /'unsafe-inline'/);
});

test("responsive layout includes phone, tablet and compact-phone breakpoints", () => {
  assert.match(source, /@media\(max-width:850px\)/);
  assert.match(source, /@media\(max-width:560px\)/);
  assert.match(source, /@media\(max-width:360px\)/);
});

test("reduced-motion preference is respected", () => {
  assert.match(source, /prefers-reduced-motion:reduce/);
});

test("assessment UI exposes the run action only when the health endpoint reports readiness", () => {
  assert.match(source, /scannerReady=health\.scanner_state==="ready"/);
  assert.match(source, /if\(scannerReady\)actions\.append\(button\("Run assessment"/);
  assert.match(source, /\.notice\[hidden\]\{display:none\}/);
});

test("assessment UI submits only to the target's passive scan endpoint", () => {
  assert.match(source, /async function runAssessment\(id,action\)/);
  assert.match(source, /\/api\/targets\/"\+encodeURIComponent\(id\)\+"\/scan/);
  assert.match(source, /redirect:"manual"/);
});

test("initial dashboard HTML reflects the server-side scanner readiness gate", () => {
  assert.ok(source.includes("function page(scannerReady=false)"));
  assert.ok(source.includes('id="scan-notice" role="note"\'+(scannerReady?" hidden":"")'));
  assert.ok(source.includes('scannerReady?"Passive-only assessment: one HTTPS GET to the verified origin'));
});
