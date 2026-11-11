# Security Assessment Alpha

Private-alpha website security configuration assessment platform built on Cloudflare Workers and D1.

## Live capabilities

- Open a private browser-bound workspace without creating an account.
- Register standard-port HTTPS website targets.
- Prove ownership using a DNS TXT record at `_secops-verification.<hostname>`.
- Discover up to 250 in-scope hostnames from public Certificate Transparency records after ownership verification.
- Check discovered hostnames using Cloudflare DNS-over-HTTPS for current A/AAAA answers.
- Run a passive HTTP configuration assessment against a verified target.
- Review scan history, observations, evidence and remediation guidance.
- Delete a target and its associated findings, assets, scans and events.

## Assessment scope

The active assessment is deliberately narrow:

- One HTTPS GET to the verified origin.
- Standard HTTPS port only.
- Redirects are not followed.
- The response body is not crawled or parsed; only response status and selected headers are inspected.
- No port scanning, crawling, exploit payloads, authentication testing, stress testing, load testing or DDoS functionality.

The UI exposes **Run assessment** only when the live health endpoint reports the scanner as ready. The Worker also enforces the release flag and the `EGRESS` binding server-side; a browser button is not a security control.

## Egress and security validation

- Production Worker binding: `EGRESS` → `cf1:network` (account default virtual network).
- Enabled Gateway L4 rule: `SECOPS scanner egress — block non-public destinations`.
- The rule matches Internet-bound Gateway traffic and blocks non-public/special-use IPv4 and IPv6 destination ranges.
- Public HTTPS egress through the Worker VPC path was confirmed (`example.com` returned HTTP 200).
- Direct private IPv4, loopback, IPv6 loopback, IPv6 ULA, IPv6 link-local and a hostname resolving to a private IPv4 address were rejected with `ProxyError: destination_ip_prohibited`.
- The IPv4 link-local metadata probe timed out; that specific runtime result is inconclusive. The destination range remains covered by the persistent Gateway policy.
- A temporary, narrowly scoped Gateway L4 rule blocking the exact public IPv6 addresses observed for `example.com` caused the Worker request to fail during TLS setup. Removing the temporary rule restored HTTP 200. The temporary rule and diagnostic Worker were deleted after the test.
- Gateway analytics showed Worker VPC as the on-ramp and Internet as the off-ramp. The sampled analytics did not provide a rule ID for the temporary blocked event, so detailed policy-log attribution remains an operational check before expanding scanner scope.

DNS preflight and Gateway destination enforcement are separate controls. The preflight checks every returned A/AAAA answer; the Gateway policy protects the actual connection if DNS changes between lookup and connect.

## Current limitations

- This is a private alpha, not a full vulnerability scanner or penetration-testing service.
- Workspace identity is a high-entropy browser cookie, not a user account. Clearing browser data can lose access.
- No MFA, RBAC, team membership or account recovery.
- Global abuse controls, workspace-level quotas, alerting and an abuse-response process still need strengthening before public launch.
- A real successful DNS TXT verification on a domain controlled by the project owner has not yet been independently exercised in this environment. The live CI lifecycle test verifies anonymous workspace creation, target registration, duplicate rejection, rejection of unverified scans and target deletion.
- No public release or broader scan features until authentication, tenant isolation, operational controls and the remaining egress/logging checks are completed.

## Development

- Worker: `worker.js`
- D1 schema: `database/schema.sql`
- Cloudflare config: `wrangler.toml`
- Security model and release criteria: `docs/SECURITY_MODEL.md`
- Tests: `npm test`
