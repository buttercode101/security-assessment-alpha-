# Security model and release gates

## Current alpha boundaries
- Browser-bound anonymous workspace cookie; no account identity, MFA, RBAC, or team membership.
- Workspace token is high entropy and only its SHA-256 hash is stored.
- HTTPS origins only; userinfo, non-standard ports, IP literals, localhost and selected special-use suffixes rejected.
- Ownership proof is DNS TXT only: `_secops-verification.<hostname>`.
- DNS A/AAAA answers are checked against a partial public-address filter.
- Redirects are not followed.
- Non-GET API calls require an exact Origin match.
- Scan route is closed unless `SCAN_EGRESS_READY === true`; do not set this flag in the current Worker.
- No crawling, exploit payloads, auth bypass, load generation, stress tests, or DDoS.

## Critical limitations (not production-safe)
1. DNS validation is not bound to the actual connection. A separate DNS lookup followed by Worker fetch can be vulnerable to rebinding/TOCTOU.
2. Public IP classification is incomplete and must not be treated as a complete special-purpose registry implementation.
3. No network-layer egress isolation, scanner sandbox, global rate limiting, bot controls, account auth, or abuse response process.
4. Cookie-based anonymous workspaces can be lost when browser data is cleared and are not suitable as a multi-user identity system.
5. Existing Worker UI uses inline script/style and currently relaxes CSP with unsafe-inline.
6. No independent live HTTP smoke test has yet confirmed runtime behaviour.

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
- Independently test SSRF, DNS rebinding, IPv4/IPv6 edge cases, redirects, tenant isolation, CSRF, XSS, quotas and failure recovery.

## AI safety
AI may summarize deterministic evidence and draft remediation. It must not expand scope, execute tests, claim exploitability, or mark a finding verified without deterministic evidence and human approval.
