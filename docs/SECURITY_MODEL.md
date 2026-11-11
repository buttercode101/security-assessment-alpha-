# Security model and release gates

## Current alpha boundaries
- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA preflight rejects malformed literals and common special-purpose ranges. This is conservative but not a complete IANA registry and is not, by itself, an SSRF control.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- The scan route requires both an `EGRESS` VPC binding and `SCAN_EGRESS_READY=enabled`. The binding is now configured, but the readiness flag remains absent, so scans remain paused.
- No crawling, exploit payloads, authentication bypass, load generation, stress tests, or DDoS.

## Current scanner infrastructure
- Cloudflare Access/Zero Trust is enabled.
- Dedicated virtual network: `secops-scanner-egress`, ID `9c798b90-809b-4f60-b7a1-b11105f71c4e`.
- That network is configured as the account default network. The production Worker binding is `EGRESS` with `network_id = "cf1:network"`, which is the documented Workers VPC path for public Internet egress through Cloudflare Gateway.
- An enabled Gateway L4 block policy is scoped to that VNet and the Internet off-ramp. It blocks configured private, loopback, link-local, shared, documentation, benchmark, multicast, reserved, transition, and non-global IPv4/IPv6 destination ranges.
- The production Worker has the D1 binding and VPC binding attached. This configuration has been verified through the Cloudflare API.
- The account currently has no Cloudflare Tunnels listed. Cloudflare's VPC documentation describes the default-network path and notes that an active Tunnel, Mesh node, or WAN on-ramp is required for access to private network services. Do not assume that a VPC binding alone proves public egress is operational.
- A temporary fixed-destination diagnostic Worker and a temporary GitHub Actions probe were created to test public HTTPS reachability and private IPv4/IPv6 destinations, including hostnames that resolve to private IPs. The browser automation provider could not execute because its wallet balance is negative, and the local runtime has no external DNS/network access. Therefore, live network-level results are still unverified. Remove temporary probe resources after completing verification.
- Cloudflare documents that Workers VPC public Internet traffic can pass through Gateway and that Gateway policies/logs apply to Workers VPC traffic. The documented Gateway public-egress path uses `cf1:network`; the explicit VNet is the account default network here.

## Critical limitations (not production-safe)
1. The production Worker has an EGRESS binding, but scanner readiness remains disabled.
2. Public HTTPS success and private IPv4/IPv6 blocking have not yet been demonstrated from the deployed Worker runtime.
3. DNS preflight is a separate lookup from the eventual connection. Gateway policy enforcement at connection time is required; preflight alone is not sufficient.
4. The anonymous browser workspace can be lost when browser data is cleared and is not a multi-user identity system.
5. No global abuse controls, bot controls, account auth, RBAC, MFA, or abuse response process.
6. Interactive browser flows and DNS ownership verification have not yet been independently exercised end-to-end. CI verifies the live health endpoint, live dashboard HTML, CSP nonce, required sections, and parses the live client script.

## Required before enabling scans
- Prove the deployed Worker's `EGRESS.fetch()` reaches a known public HTTPS destination.
- Prove Gateway blocks loopback, RFC1918, CGNAT, link-local, documentation, benchmark, multicast, reserved, transition, IPv4-mapped IPv6, and other non-global IPv4/IPv6 destinations.
- Prove hostnames resolving to private or mixed public/private A/AAAA answers cannot bypass the Gateway block (DNS rebinding).
- Verify Gateway Network logs attribute the requests to Workers VPC and show policy enforcement.
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
