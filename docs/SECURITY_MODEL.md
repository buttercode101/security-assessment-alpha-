# Security model and release gates

## Current alpha boundaries
- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA preflight rejects malformed literals and common special-purpose ranges. This is conservative but not a complete IANA registry and is not, by itself, an SSRF control.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- The scan route requires both an `EGRESS` VPC binding and `SCAN_EGRESS_READY=enabled`. The binding is configured, but the readiness flag remains absent, so scans remain paused.
- No crawling, exploit payloads, authentication bypass, load generation, stress tests, or DDoS.

## Current scanner infrastructure
- Cloudflare Access/Zero Trust is enabled.
- Dedicated virtual network: `secops-scanner-egress`, ID `9c798b90-809b-4f60-b7a1-b11105f71c4e`.
- That network is configured as the account default network. The production Worker binding is `EGRESS` with `network_id = "cf1:network"`, the documented Workers VPC path for public Internet egress through Cloudflare Gateway.
- An enabled Gateway L4 block policy is configured to block loopback, private, link-local, shared, documentation, benchmark, multicast, reserved, transition, and non-global IPv4/IPv6 destination ranges. Gateway analytics showed the Worker on-ramp but did not provide a populated virtual network ID. Cloudflare's published Traffic Source selector values do not list Workers VPC, so the unverified `net.onramp.type == "workers_vpc"` condition was removed. The rule now uses the documented `net.offramp.type == "internet"` selector and the destination CIDR list.
- The production Worker has the D1 binding and VPC binding attached. This configuration has been verified through the Cloudflare API.
- The account currently has no Cloudflare Tunnels or Mesh nodes listed. The account's VPC binding does not establish private-network reachability.
- Live runtime probes executed from a temporary Worker through the production-style `EGRESS` VPC binding and wrote results to the existing D1 database. Public HTTPS to `example.com` returned HTTP 200 in repeated runs. Direct loopback/private IPv4, IPv6 loopback/ULA/link-local, and hostnames resolving to private IPv4 were rejected with `ProxyError: destination_ip_prohibited`.
- The IPv4 link-local probe timed out; its result is inconclusive.
- Gateway analytics confirmed Worker traffic exits through the Internet off-ramp, but the original rule's VNet selector could not match because `virtualNetworkId` was empty. An attempted Workers VPC Traffic Source selector was not supported by Cloudflare's published selector value list and has been removed. The persistent policy now relies on the documented Internet off-ramp selector plus destination CIDRs. It still requires a post-change probe showing the configured rule ID and block action. Do not treat runtime `destination_ip_prohibited` errors alone as proof that Gateway enforced the CIDR policy.
- Gateway activity logging is enabled with DNS, HTTP, and L4 events and PII redaction. The relevant Gateway activity records still need to be inspected in Zero Trust > Insights > Logs, including Traffic Source, Traffic Destination, policy action, and rule name. Workers Observability logs alone do not prove Gateway enforcement.
- The Zero Trust account currently has no Gateway locations, TLS inspection is disabled, and the Gateway certificate binding reports `pending_deployment`. These are additional configuration facts to account for while verifying policy behavior; no causal conclusion has been established.
- The temporary diagnostic Worker, its cron trigger and subdomain, temporary Gateway test rules, temporary GitHub Actions workflows, and D1 probe table were removed after testing. The production Worker, scanner VNet, and corrected persistent L4 policy were left intact.

## Critical limitations (not production-safe)
1. The production Worker has an EGRESS binding, but scanner readiness remains disabled.
2. Public HTTPS success and runtime private-address rejection have been demonstrated; Gateway policy attribution and enforcement have not.
3. IPv4 link-local behavior remains unverified.
4. DNS preflight is a separate lookup from the eventual connection. Gateway policy enforcement at connection time is required; preflight alone is not sufficient.
5. The anonymous browser workspace can be lost when browser data is cleared and is not a multi-user identity system.
6. No global abuse controls, bot controls, account auth, RBAC, MFA, or abuse response process.
7. Interactive browser flows and DNS ownership verification have not yet been independently exercised end-to-end. CI verifies the live health endpoint, live dashboard HTML, CSP nonce, required sections, and parses the live client script.

## Required before enabling scans
- Keep the deployed Worker's `EGRESS.fetch()` public HTTPS path working.
- Prove Gateway blocks loopback, RFC1918, CGNAT, link-local, documentation, benchmark, multicast, reserved, transition, IPv4-mapped IPv6, and other non-global IPv4/IPv6 destinations.
- Prove hostnames resolving to private or mixed public/private A/AAAA answers cannot bypass the destination block (DNS rebinding).
- Verify Gateway Network/HTTP logs attribute requests to Workers VPC and show the expected policy enforcement and rule name.
- Prove the corrected Internet-off-ramp L4 policy blocks a test destination and the non-public IPv4/IPv6 CIDR list, with matching Gateway logs and the persistent rule ID.
- Keep redirects disabled; if redirect support is ever added, revalidate every destination.
- Restrict protocol and port to HTTPS/443.
- Add global and per-workspace/per-target rate limits, concurrency caps, request timeouts, response byte caps and an emergency stop.
- Separate control plane from scanner runtime and use a durable queue before adding crawling or broader checks.
- Authenticate users and implement tenant-scoped authorization on every object access.
- Add audit events, abuse reporting, retention/deletion policy and operational alerting.
- Independently test SSRF, DNS rebinding, IPv4/IPv6 edge cases (including malformed literals, mapped addresses, transition and documentation ranges), redirects, tenant isolation, CSRF, XSS, quotas and failure recovery.

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
