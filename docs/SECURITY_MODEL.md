# Security model and release gates

## Current alpha boundaries
- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA answers are checked against conservative IPv4/IPv6 syntax and common special-purpose, documentation and transition-range filters; this is not a complete IANA registry implementation.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- Scan route is closed unless `SCAN_EGRESS_READY === true`; do not set this flag in the current Worker.
- No crawling, exploit payloads, auth bypass, load generation, stress tests, or DDoS.

## Critical limitations (not production-safe)
1. DNS validation is not bound to the actual connection. A separate DNS lookup followed by Worker fetch can be vulnerable to rebinding/TOCTOU.
2. Public IP classification is deliberately conservative but incomplete. It is a preflight guard only, not a complete IANA special-purpose registry implementation or a substitute for connect-time egress enforcement.
3. No network-layer egress isolation, scanner sandbox, global rate limiting, bot controls, account auth, or abuse response process.
4. Cookie-based anonymous workspaces can be lost when browser data is cleared and are not suitable as a multi-user identity system.
5. The dashboard uses inline script/style with per-response CSP nonces. CI now checks the live health endpoint, live dashboard HTML, CSP nonce, required sections, and parses the live client script; interactive browser actions still need a separate E2E session.
6. Live health and dashboard HTML responses have been checked, but interactive browser flows and DNS ownership verification have not yet been independently exercised end-to-end.

## Required before enabling scans
- Move outbound requests into an isolated scanner service/network with deny-by-default egress.
- Enforce destination IP policy at connect time, not just during preflight DNS.
- Resolve and validate all A/AAAA/CNAME chains; pin validated destination; reject mixed public/private answer sets.
- Revalidate every redirect and default to not following redirects.
- Restrict protocol and port to HTTPS/443.
- Add global and per-workspace/per-target rate limits, concurrency caps, request timeouts, response byte caps and emergency stop.
- Separate control plane from scanner runtime and use a durable queue.
- Authenticate users and implement tenant-scoped authorization on every object access.
- Add audit events, abuse reporting, retention/deletion policy and operational alerting.
- Independently test SSRF, DNS rebinding, IPv4/IPv6 edge cases (including malformed literals, mapped addresses, transition and documentation ranges), redirects, tenant isolation, CSRF, XSS, quotas and failure recovery.
- Keep runtime request tests in CI for origin enforcement, cookie attributes, target URL validation and the scan feature gate.

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
