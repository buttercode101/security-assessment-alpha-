import test from "node:test";
import assert from "node:assert/strict";
import {
  public4,
  public6,
  classifyDnsAnswers,
  extractCtAssets,
} from "../worker.js";

test("IPv4 public-address gate rejects special-use and private ranges", () => {
  const blocked = [
    "0.0.0.0", "10.1.2.3", "100.64.0.1", "100.127.255.254",
    "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.254",
    "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1",
    "198.18.0.1", "198.19.255.254", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1",
    "255.255.255.255",
  ];
  for (const address of blocked) assert.equal(public4(address), false, address);
});

test("IPv4 public-address gate accepts ordinary globally routable addresses", () => {
  const allowed = [
    "1.1.1.1", "8.8.8.8", "93.184.216.34", "172.15.255.255",
    "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.1.1.1",
    "198.17.255.255", "198.20.0.1", "203.1.1.1", "223.255.255.255",
  ];
  for (const address of allowed) assert.equal(public4(address), true, address);
});

test("IPv4 parser rejects malformed, abbreviated, and non-canonical literals", () => {
  for (const address of [
    "", "127.1", "1.2.3", "1.2.3.4.5", "256.1.1.1",
    "-1.2.3.4", "01.2.3.4", "1.2.3.999", "1.2.3.a",
    " 1.1.1.1", "1.1.1.1 ",
  ]) assert.equal(public4(address), false, address);
});

test("IPv6 public-address gate rejects loopback, unspecified, ULA, link-local and multicast", () => {
  for (const address of [
    "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1",
    "febf::1", "ff02::1", "100::1", "2001::1",
    "2001:db8::1", "2002::1", "3fff::1", "4000::1",
    "5f00::1", "8000::1", "::ffff:127.0.0.1",
  ]) assert.equal(public6(address), false, address);
});

test("IPv6 public-address gate accepts ordinary global unicast addresses", () => {
  for (const address of [
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
    "2a00:1450:4001::1",
  ]) assert.equal(public6(address), true, address);
});

test("IPv6 parser rejects malformed literals and zone identifiers", () => {
  for (const address of [
    "", "localhost", "2001:4860::gggg", "2001:4860::1%eth0",
    "2001:4860:4860:4860:4860:4860:4860:4860:4860",
    "2001:4860:4860:4860:4860:4860:4860",
    "2001:4860::1.2.3.4", " 2001:4860::1",
  ]) assert.equal(public6(address), false, address);
});

test("DNS classification returns no-record when no A or AAAA answers exist", () => {
  assert.deepEqual(classifyDnsAnswers([], [{ type: 5, data: "alias.example.com" }]), {
    status: "no-record",
    addresses: [],
  });
});

test("DNS classification deduplicates addresses and ignores non-address records", () => {
  assert.deepEqual(classifyDnsAnswers(
    [{ type: 1, data: "1.1.1.1" }, { type: 1, data: "1.1.1.1" }, { type: 5, data: "x.example" }],
    [{ type: 28, data: "2606:4700:4700::1111" }],
  ), {
    status: "public-dns",
    addresses: ["1.1.1.1", "2606:4700:4700::1111"],
  });
});

test("DNS classification marks any private or reserved answer as unsafe", () => {
  assert.equal(classifyDnsAnswers(
    [{ type: 1, data: "1.1.1.1" }, { type: 1, data: "10.0.0.1" }],
    [],
  ).status, "reserved-address");
  assert.equal(classifyDnsAnswers(
    [],
    [{ type: 28, data: "2606:4700:4700::1111" }, { type: 28, data: "fd00::1" }],
  ).status, "reserved-address");
});

test("DNS classification checks every answer even when display output is capped at ten", () => {
  const publicAnswers = Array.from({ length: 10 }, (_, i) => ({
    type: 1,
    data: `8.8.4.${i + 1}`,
  }));
  const result = classifyDnsAnswers(
    [...publicAnswers, { type: 1, data: "127.0.0.1" }],
    [],
  );
  assert.equal(result.status, "reserved-address");
  assert.equal(result.addresses.length, 10);
  assert.equal(result.addresses.includes("127.0.0.1"), false);
});

test("certificate transparency extraction keeps only valid in-scope subdomains", () => {
  const assets = extractCtAssets([
    {
      name_value: "*.www.example.com\nexample.com\napi.example.com,evil-example.com\nUPPER.Example.com.",
      not_before: "2026-01-01T00:00:00",
      not_after: "2027-01-01T00:00:00",
      issuer_name: "Example CA",
    },
    { name_value: "api.example.com\ninvalid..example.com\n-unsafe.example.com\nunsafe-.example.com" },
  ], "example.com");
  assert.deepEqual(assets.map((asset) => asset.hostname), [
    "api.example.com",
    "upper.example.com",
    "www.example.com",
  ]);
  assert.equal(assets[0].issuer_name, "Example CA");
});

test("certificate transparency extraction enforces a hostname boundary", () => {
  const assets = extractCtAssets([
    { name_value: "example.com\nnotexample.com\nevil-example.com\nsub.example.com\nsub.example.com.attacker.test" },
  ], "example.com");
  assert.deepEqual(assets.map((asset) => asset.hostname), ["sub.example.com"]);
});

test("certificate transparency extraction deduplicates and retains the newest certificate metadata", () => {
  const assets = extractCtAssets([
    { name_value: "api.example.com", not_before: "2025-01-01", issuer_name: "Old CA" },
    { name_value: "api.example.com", not_before: "2026-01-01", issuer_name: "New CA" },
  ], "example.com");
  assert.equal(assets.length, 1);
  assert.equal(assets[0].issuer_name, "New CA");
});

test("certificate transparency extraction caps results at 250 hostnames", () => {
  const names = Array.from({ length: 300 }, (_, i) => `host${String(i).padStart(3, "0")}.example.com`);
  const assets = extractCtAssets([{ name_value: names.join("\n") }], "example.com");
  assert.equal(assets.length, 250);
  assert.equal(assets[0].hostname, "host000.example.com");
  assert.equal(assets.at(-1).hostname, "host249.example.com");
});

test("certificate transparency extraction rejects invalid root and malformed records", () => {
  assert.deepEqual(extractCtAssets(null, "example.com"), []);
  assert.deepEqual(extractCtAssets([{ name_value: 123 }], "example.com"), []);
  assert.deepEqual(extractCtAssets([{ name_value: "a.example.com" }], ""), []);
});
