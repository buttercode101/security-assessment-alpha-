# Security model and release gates

## Current alpha boundaries

- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA preflight rejects malformed literals and common special-purpose ranges. It is conservative and is not, by itself, an SSRF control.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- The scan route requires both an `EGRESS` VPC binding and `SCAN_EGRESS_READY=enabled`. Both are now deployed.
- The scan route performs one HTTPS GET to the verified origin, reads response status and selected headers, does not follow redirects and does not crawl or parse the response body.
- No crawling, exploit payloads, authentication bypass, port scanning, load generation, stress tests, or DDoS.

## Scanner egress infrastructure

- Cloudflare Access/Zero Trust is enabled.
- Dedicated virtual network: `secops-scanner-egress`, ID `9c798b90-809b-4f60-b7a1-b11105f71c4e`.
- That network is configured as the account default network. The production Worker binding is `EGRESS` with `network_id = "cf1:network"`, the documented Workers VPC path for public Internet egress through Cloudflare Gateway.
- Production D1 binding: `DB` → `secops-platform-core`.
- Production release flag: `SCAN_EGRESS_READY=enabled`.
- Enabled persistent Gateway L4 rule: `SECOPS scanner egress — block non-public destinations`, ID `d8d3c5b9-ac23-4694-a776-5db5c6a6fbaf`.
- The persistent rule matches Internet-bound Gateway traffic and blocks loopback, private, link-local, shared, documentation, benchmark, multicast, reserved, transition, and non-global IPv4/IPv6 destination ranges. It uses `net.offramp.type == "internet"` plus destination CIDRs; it does not rely on an unsupported Workers VPC Traffic Source selector.
- Important scope note: because the supported expression does not include a reliable Workers VPC-only source selector, this persistent rule applies to matching Internet-bound Gateway traffic at the account level, not only this Worker. It does not create private-network reachability.
- Gateway logging is enabled for DNS, HTTP and L4, with PII redaction.

## Observed egress validation

Tests were executed from a temporary Worker using the same `cf1:network` VPC binding. That Worker accepted no user-supplied URLs and was deleted after the test.

- Public HTTPS to `example.com` returned HTTP 200 in repeated runs.
- Direct private IPv4, loopback, IPv6 loopback, IPv6 ULA, IPv6 link-local and a hostname resolving to private IPv4 returned `ProxyError: destination_ip_prohibited`.
- The IPv4 link-local metadata probe timed out. That individual result is inconclusive; the range remains covered by the persistent Gateway policy.
- Gateway analytics showed Worker VPC as the on-ramp and Internet as the off-ramp.
- A controlled policy A/B test added a temporary L4 block rule for the exact public IPv6 addresses observed for `example.com`. The previously successful request then failed during TLS setup; after deleting the temporary rule, the request returned HTTP 200 again.
- Gateway L4 analytics recorded two `action: block` sessions with temporary test rule ID `9af7394d-d42a-4b23-8d00-5ed8624bdcd0`, on-ramp `workers_vpc`, off-ramp `internet`, and SNI `example.com`. This is direct evidence that Gateway L4 policy enforcement applies to Workers VPC egress.
- The temporary rule, diagnostic Worker and its workers.dev subdomain were deleted. The persistent non-public-destination rule was left enabled. The temporary test rule ID is historical evidence only; it is not the ID of the persistent rule.

The VPC proxy's `destination_ip_prohibited` responses show that the tested private/special-use destinations did not connect, but those errors alone do not identify which Cloudflare layer rejected each destination. The separate Gateway A/B test demonstrates that Gateway policy enforcement is on the egress path.

## Critical limitations

1. This remains a private alpha, not a full vulnerability scanner or penetration-testing service.
2. A successful DNS TXT verification on a domain controlled by the project owner has not yet been independently exercised in this environment. The live CI lifecycle test checks anonymous workspace creation, target registration, duplicate rejection, rejection of unverified scans and target deletion.
3. The IPv4 link-local metadata probe timed out and remains inconclusive.
4. The persistent Gateway rule is account-scoped for matching Internet-bound traffic because a supported Workers VPC-only Traffic Source selector was not available.
5. The anonymous browser workspace can be lost when browser data is cleared and is not a multi-user identity system.
6. No global abuse controls, account auth, RBAC, MFA, account recovery or abuse response process.
7. No real owner-controlled target has been run through the complete DNS TXT → assessment → history → deletion journey in this environment.
8. No broader scan features should be added until policy-log attribution, real owner-domain verification, IPv4 link-local behavior, tenant isolation, quotas and abuse controls are independently validated.

## Required before public release or broader scanning

- Independently complete a real DNS TXT ownership challenge on a domain the project owner controls.
- Confirm Gateway Network/HTTP logs attribute requests to Workers VPC and show the expected persistent rule name and policy action.
- Resolve the IPv4 link-local probe ambiguity.
- Add global and per-workspace/per-target rate limits, concurrency caps, request timeouts, response byte caps and an emergency stop before adding any additional request types.
- Authenticate users and implement tenant-scoped authorization on every object access before multi-user use.
- Add audit events, abuse reporting, retention/deletion policy and operational alerting.
- Independently test SSRF, DNS rebinding, IPv4/IPv6 edge cases (including malformed literals, mapped addresses, transition and documentation ranges), redirects, tenant isolation, CSRF, XSS, quotas and failure recovery.
- Keep redirects disabled; if redirect support is ever added, revalidate every destination.
- Keep scanner requests restricted to HTTPS/443 and owner-verified targets.

## Passive asset discovery

- Only a DNS-TXT-verified target can trigger certificate transparency discovery.
- The Worker queries the fixed `crt.sh` JSON endpoint; the verified hostname is sent to that public third-party service.
- Returned SAN names are normalized, deduplicated, checked against an exact hostname suffix boundary, limited to 250 hostnames, and persisted with certificate dates and issuer metadata.
- Response bodies are streamed with a 2 MB cap and a 25-second timeout. Successful discovery is rate-limited to once per hour per target.
- Discovery itself does not resolve or connect to discovered hosts. Optional DNS checks query Cloudflare DNS-over-HTTPS for A/AAAA records, classify public versus reserved answers, and store the result. They do not open an HTTP/TCP connection to the hostname.
- DNS checks are limited to one per asset every five minutes. DNS answers do not prove HTTP availability or security.

## Workspace lifecycle

- Assessment history is returned through a workspace-scoped query.
- Finding details include stored evidence and remediation text; the UI renders these values using text nodes.
- Target deletion verifies workspace ownership, then explicitly removes findings, discovered assets, scan events, scans, and the target in dependency order.

## AI safety

AI may summarize deterministic evidence and draft remediation. It must not expand scope, execute tests, claim exploitability, or mark a finding verified without deterministic evidence and human approval.
