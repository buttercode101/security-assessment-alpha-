import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import worker, { public4, public6, extractCtAssets } from "../worker.js";

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
          if (sql.includes("SELECT id FROM targets WHERE id=? AND workspace_id=?")) return values[0] === "00000000-0000-4000-8000-000000000000" ? { id: values[0] } : null;
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

test("dashboard response uses a fresh nonce for inline assets and a restrictive CSP", async () => {
  const { env } = makeEnv();
  const first = await worker.fetch(new Request("https://alpha.test/"), env);
  const second = await worker.fetch(new Request("https://alpha.test/"), env);
  assert.equal(first.status, 200);
  const html = await first.text();
  const csp = first.headers.get("content-security-policy");
  const nonce = csp.match(/script-src 'self' 'nonce-([^']+)'/)?.[1];
  assert.ok(nonce, "CSP should define a script nonce");
  assert.ok(html.includes('<style nonce="' + nonce + '">'), "HTML should contain the exact CSP nonce on its style element");
  assert.ok(html.includes('<script nonce="' + nonce + '">'), "HTML should contain the exact CSP nonce on its script element");
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.notEqual(csp, second.headers.get("content-security-policy"), "nonce should rotate per response");
});


test("IPv4 public-address filter rejects special-purpose and documentation ranges precisely", () => {
  for (const ip of [
    "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254",
    "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.254",
    "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1",
    "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1",
    "224.0.0.1", "240.0.0.1", "255.255.255.255"
  ]) assert.equal(public4(ip), false, ip);
  for (const ip of ["1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "198.51.99.1", "198.52.0.1", "203.0.112.1"]) {
    assert.equal(public4(ip), true, ip);
  }
  for (const ip of ["999.1.1.1", "1.2.3", "1.2.3.4.5", "1.a.3.4", "1..2.3", "01.2.3.4"]) assert.equal(public4(ip), false, ip);
});

test("IPv6 public-address filter rejects non-global, transition and documentation ranges", () => {
  for (const ip of [
    "::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
    "2001:0:1::1", "2001:db8::1", "2002:c000:0201::1",
    "3fff:0001::1", "::ffff:8.8.8.8"
  ]) assert.equal(public6(ip), false, ip);
  for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450::1", "3fff:1000::1"]) {
    assert.equal(public6(ip), true, ip);
  }
  for (const ip of ["not-an-ip", "2001:::1", "2001:db8::1%eth0", "2001:4860::1.2.3.4", "2001:4860:::1", "2001:4860:1:2:3:4:5:6:7"]) assert.equal(public6(ip), false, ip);
});


test("target deletion is tenant-scoped and removes dependent records in order", async () => {
  const { env, writes } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets/00000000-0000-4000-8000-000000000000", {
    method: "DELETE",
    headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
    body: "{}"
  }), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { deleted: true, id: "00000000-0000-4000-8000-000000000000" });
  const deletes = writes.filter(item => item.sql.startsWith("DELETE FROM")).map(item => item.sql.split(" ")[2]);
  assert.deepEqual(deletes, ["findings", "scan_events", "scans", "targets"]);
});

test("scan history is returned only for the current workspace", async () => {
  const { env } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/scans", { headers: { cookie } }), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { scans: [] });
});


test("target deletion does not disclose or delete another workspace target", async () => {
  const { env, writes } = makeEnv();
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets/11111111-1111-4111-8111-111111111111", {
    method: "DELETE",
    headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
    body: "{}"
  }), env);
  assert.equal(response.status, 404);
  assert.equal(writes.some(item => item.sql.startsWith("DELETE FROM")), false);
});


test("string environment flag cannot open the boolean-only scan gate", async () => {
  const { env } = makeEnv();
  env.SCAN_EGRESS_READY = "true";
  const cookie = await createSession(env);
  const response = await worker.fetch(new Request("https://alpha.test/api/targets/00000000-0000-4000-8000-000000000000/scan", {
    method: "POST",
    headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
    body: "{}"
  }), env);
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /temporarily paused/);
});


test("dashboard client JavaScript parses and all referenced primary controls exist", async () => {
  const { env } = makeEnv();
  const response = await worker.fetch(new Request("https://alpha.test/"), env);
  const html = await response.text();
  const scriptStart = html.indexOf('<script nonce="');
  const scriptBodyStart = html.indexOf(">", scriptStart) + 1;
  const scriptEnd = html.indexOf("</script>", scriptBodyStart);
  assert.ok(scriptStart >= 0 && scriptEnd > scriptBodyStart, "nonce-protected client script should exist");
  assert.doesNotThrow(() => new vm.Script(html.slice(scriptBodyStart, scriptEnd)), "dashboard JavaScript should parse");
  for (const id of ["form", "url", "add", "targets", "scans", "findings", "refresh", "tc", "sc", "fc"]) {
    assert.ok(html.includes('id="' + id + '"'), "dashboard is missing #" + id);
  }
});


test("certificate transparency parser keeps only names inside the verified domain and deduplicates", () => {
  const assets = extractCtAssets([
    { name_value: "api.example.org\n*.staging.example.org\nexample.org\nnotexample.org\nmail.other.net", not_before: "2025-01-01", not_after: "2025-04-01", issuer_name: "Issuer A" },
    { name_value: "api.example.org\nshop.example.org", not_before: "2026-01-01", not_after: "2026-04-01", issuer_name: "Issuer B" },
    { name_value: "*.bad..example.org\n-evil.example.org\nfoo_example.org" }
  ], "example.org");
  assert.deepEqual(assets.map(x => x.hostname), ["api.example.org", "shop.example.org", "staging.example.org"]);
  assert.equal(assets[0].certificate_not_before, "2026-01-01");
  assert.equal(assets[0].issuer_name, "Issuer B");
});

test("certificate transparency parser enforces hostname boundaries", () => {
  assert.deepEqual(extractCtAssets([{ name_value: "example.org\nnotexample.org\nsub.example.org.attacker.net" }], "example.org"), []);
});

test("asset discovery is available only after ownership verification and stores passive CT evidence", async () => {
  const { env, writes } = makeEnv();
  const cookie = await createSession(env);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.match(String(url), /^https:\\/\\/crt\\.sh\\//);
    return new Response(JSON.stringify([{ name_value: "api.example.org\nshop.example.org", not_before: "2026-01-01", not_after: "2026-04-01", issuer_name: "Test CA" }]), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const response = await worker.fetch(new Request("https://alpha.test/api/targets/00000000-0000-4000-8000-000000000000/discover", {
      method: "POST",
      headers: { cookie, origin: "https://alpha.test", "content-type": "application/json" },
      body: "{}"
    }), env);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.assets_discovered, 2);
    assert.equal(body.source, "certificate-transparency");
    assert.match(body.note, /do not confirm that a host is currently live/);
    assert.equal(writes.filter(x => x.sql.includes("INSERT INTO discovered_assets")).length, 2);
    assert.ok(writes.some(x => x.sql.includes("UPDATE targets SET last_discovery_at")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
