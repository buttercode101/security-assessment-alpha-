import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.js";

function makeEnv() {
  const writes = [];
  const db = {
    prepare(sql) {
      let values = [];
      return {
        bind(...args) { values = args; return this; },
        async first() {
          if (sql.includes("SELECT id FROM workspaces WHERE token_hash")) return { id: "workspace-test" };
          if (sql.includes("SELECT id FROM targets WHERE workspace_id")) return null;
          if (sql.includes("SELECT * FROM targets WHERE id=? AND workspace_id=?")) return { id: "00000000-0000-4000-8000-000000000000", verified_at: "2026-11-11T00:00:00.000Z", last_scan_at: null, hostname: "example.org", url: "https://example.org" };
          if (sql.includes("SELECT COUNT(*) n FROM targets")) return { n: 0 };
          return null;
        },
        async all() { return { results: [] }; },
        async run() { writes.push({ sql, values }); return { success: true }; }
      };
    }
  };
  return { env: { DB: db }, writes };
}

async function createSession(env) {
  const response = await worker.fetch(new Request("https://alpha.test/api/session"), env);
  assert.equal(response.status, 200);
  return response.headers.get("set-cookie");
}

test("health endpoint is available without creating a workspace", async () => {
  const { env } = makeEnv();
  const response = await worker.fetch(new Request("https://alpha.test/api/health"), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: "security-assessment-alpha",
    mode: "passive-only"
  });
});

test("new workspace cookie is Secure, HttpOnly and SameSite=Strict", async () => {
  const { env } = makeEnv();
  const cookie = await createSession(env);
  assert.match(cookie, /^__Host-secops_ws=/);
  assert.match(cookie, /; Secure/);
  assert.match(cookie, /; HttpOnly/);
  assert.match(cookie, /; SameSite=Strict/);
  assert.match(cookie, /; Path=\//);
});

test("cross-origin state-changing requests are rejected before processing", async () => {
  const { env } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets", {
    method: "POST",
    headers: { cookie, origin: "https://attacker.test", "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.org" })
  }), env);
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /Cross-origin/);
});

test("target registration rejects non-HTTPS, credentials, custom ports, IPs and local names", async () => {
  const { env } = makeEnv();
  const cookie = await createSession(env);
  const invalid = [
    "http://example.org",
    "https://user:pass@example.org",
    "https://example.org:8443",
    "https://127.0.0.1",
    "https://localhost",
    "https://service.internal",
    "https://service.example"
  ];
  for (const url of invalid) {
    const response = await worker.fetch(new Request("https://alpha.test/api/targets", {
      method: "POST",
      headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
      body: JSON.stringify({ url })
    }), env);
    assert.equal(response.status, 400, url);
  }
});

test("valid HTTPS target is normalized to its origin and stored as pending verification", async () => {
  const { env, writes } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets", {
    method: "POST",
    headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
    body: JSON.stringify({ url: "https://Example.org/path?campaign=1#section" })
  }), env);
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.hostname, "example.org");
  assert.equal(body.verification_token.startsWith("secops_"), true);
  assert.match(body.id, /^[0-9a-f-]{36}$/);
  const insert = writes.find(item => item.sql.includes("INSERT INTO targets"));
  assert.ok(insert, "target insert should be persisted");
  assert.equal(insert.values[2], "https://example.org");
  assert.equal(insert.values[3], "example.org");
});

test("scan route returns a pause response for an owned target while isolation gate is unset", async () => {
  const { env } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets/00000000-0000-4000-8000-000000000000/scan", {
    method: "POST",
    headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
    body: "{}"
  }), env);
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /temporarily paused/);
  assert.equal(env.SCAN_EGRESS_READY, undefined);
});
