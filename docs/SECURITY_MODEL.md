# Security model and release gates

## Current alpha boundaries
- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA preflight rejects malformed literals and common special-purpose ranges. This is conservative but not a complete IANA registry and is not, by itself, an SSRF control.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- The scan route requires both an `EGRESS` VPC binding and `SCAN_EGRESS_READY=enabled`. Neither is configured in production, so scans remain paused.
- No crawling, exploit payloads, authentication bypass, load generation, stress tests, or DDoS.

## Current scanner infrastructure decision
- The preferred low-cost route is Cloudflare Workers VPC plus a dedicated Gateway L4 policy. Cloudflare documents Workers VPC as available on Free and Paid plans while in beta, and documents Gateway policies applying to Worker-originated internet traffic.
- The connected account has not enabled Access/Zero Trust. The Gateway API returned `access.api.error.not_enabled` and instructed an administrator to enable Access in the Cloudflare dashboard.
- A temporary dedicated virtual network was created while testing the API and immediately deleted after Gateway policy creation was rejected. The account currently has no virtual networks or Gateway rules.
- Do not add the `EGRESS` binding or set `SCAN_EGRESS_READY=enabled` until Access is enabled, a dedicated virtual network is created, and a scoped Gateway policy blocks private, loopback, link-local, CGNAT, documentation, multicast, reserved, transition, and non-global destination ranges.
- Before opening the gate, independently prove that public HTTPS destinations work and private IPv4/IPv6 destinations are blocked at the network layer, including DNS-rebinding attempts. The scanner must continue to reject redirects and use HTTPS/443 only.

## Critical limitations (not production-safe)
1. The production Worker currently has no `EGRESS` binding. The health endpoint reports `scanner_state: paused`.
2. DNS preflight is a separate lookup from the eventual connection. The future Gateway policy is required to block non-public destinations at connection time; preflight alone is not sufficient.
3. The anonymous browser workspace can be lost when browser data is cleared and is not a multi-user identity system.
4. No global abuse controls, bot controls, account auth, RBAC, MFA, or abuse response process.
5. Interactive browser flows and DNS ownership verification have not yet been independently exercised end-to-end. CI verifies the live health endpoint, live dashboard HTML, CSP nonce, required sections, and parses the live client script.

## Required before enabling scans
- Enable Cloudflare Access/Zero Trust in the account dashboard.
- Create a dedicated VPC network and a Gateway L4 block policy scoped only to that network.
- Bind the Worker to that VPC network using `EGRESS`; verify Gateway logs show the scanner's traffic.
- Enforce destination IP policy at the network layer; resolve and validate all A/AAAA/CNAME answers and reject mixed public/private sets.
- Revalidate every redirect and default to not following redirects.
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
