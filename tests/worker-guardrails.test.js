import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../worker.js", import.meta.url), "utf8");

test("scan route is closed unless the explicit isolation gate is true", () => {
  assert.match(source, /if\(e\.SCAN_EGRESS_READY!==true\)return json\(\{error:/);
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

test("UI tells the truth that scanning is paused", () => {
  assert.match(source, /Assessments are temporarily paused/);
});
