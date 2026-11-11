# Alpha acceptance and verification

## Verified in the current production release

- [x] Cloudflare Worker deployed with D1 and VPC EGRESS bindings.
- [x] DNS-answer classifier inspects every A/AAAA answer, including answers beyond the ten-address display cap.
- [x] Workspace cookie is Secure, HttpOnly, SameSite=Strict.
- [x] Ownership verification is DNS TXT only.
- [x] Exact Origin required for non-GET API routes.
- [x] Scan route fails closed unless both EGRESS and SCAN_EGRESS_READY are present.
- [x] Scanner readiness is enabled only after public egress and Gateway policy-path testing.
- [x] Live health endpoint returns 200 with mode=passive-only, scanner_state=ready and egress=gateway-vpc.
- [x] Live dashboard returns 200, has a per-response CSP nonce, no unsafe-inline policy, and valid client JavaScript.
- [x] Live dashboard includes target, history, asset, finding, DNS-check and Run assessment UI.
- [x] Live anonymous API lifecycle: session without signup, target registration, duplicate rejection, unverified scan rejection, target deletion and absence after deletion.
- [x] 52 Node tests passed in GitHub Actions at the time of the recorded run. Additional DNS TXT success/rejection tests are now in the latest CI run.
- [x] Public HTTPS through the production-style Workers VPC binding returned HTTP 200.
- [x] Private IPv4, loopback, IPv6 loopback, IPv6 ULA, IPv6 link-local and DNS-to-private probes were rejected by the VPC proxy.
- [x] Controlled Gateway L4 A/B test: a temporary block for the exact example.com IPv6 destinations made the request fail; removing the rule restored HTTP 200.
- [x] Gateway analytics recorded two `action: block` sessions for the temporary rule ID `9af7394d-d42a-4b23-8d00-5ed8624bdcd0`, with Workers VPC on-ramp and Internet off-ramp.
- [x] Temporary diagnostic Worker, temporary Gateway rules and temporary egress test resources were deleted.

## Not yet independently verified

- [ ] Successful DNS TXT ownership verification against a domain controlled by the project owner. No DNS zone for an owner-controlled test domain is attached to the connected Cloudflare account, and no registrar DNS-write integration is available in this workflow.
- [ ] A real owner-verified target run through the full UI journey: DNS TXT → passive assessment → history/findings → deletion. We will not scan a third-party domain or bypass the ownership proof to manufacture this result.
- [ ] IPv4 link-local metadata probe: the request timed out, so the individual runtime result is inconclusive. The address range remains in the persistent Gateway CIDR block policy.
- [ ] A direct block event for the persistent non-public-destination rule ID. The controlled temporary-rule A/B test proves Gateway enforcement on the Workers VPC path and exposes the temporary rule ID; private destinations also fail closed at the VPC proxy, so a persistent-rule match event has not yet been observed.
- [ ] Cross-workspace object access is denied.
- [ ] Independent CSP and responsive-layout visual review on 320, 360, 375, 768, 1024 and 1440 px.
- [ ] Keyboard-only and screen-reader pass.
- [ ] Browser console/network error-free pass.
- [ ] Global abuse limits, concurrency caps, account auth, tenant RBAC and alerting.

## Required test matrix

| Area | Cases | Expected |
|---|---|---|
| URL intake | HTTP, credentials, IP literal, localhost, private suffix, non-443 port | Rejected |
| Ownership | Correct TXT, absent TXT, wrong TXT, DNS timeout | Only exact TXT succeeds |
| Sessions | No cookie, valid cookie, invalid cookie, cookie theft assumptions | Isolated workspace |
| CSRF | Missing Origin, foreign Origin, exact Origin | Reject, reject, accept |
| Tenant isolation | Target/scan/finding IDs from another workspace | 404/denied |
| Scan gate | Missing EGRESS, missing release flag, unverified target, verified target | 503, 503, 403, passive assessment only |
| Abuse | Target quota, rapid retries, request floods | Must be bounded and logged before public release |
| SSRF | RFC1918, loopback, link-local, CGNAT, IPv6 local, mixed DNS, CNAME rebinding | Blocked at connection time |
| UI | 320/360/375/768/1024/1440 widths, long domains, errors, empty/loading states | No overflow or broken controls |
| Accessibility | Keyboard, focus, contrast, labels, reduced motion | WCAG 2.2 AA target |

## Evidence

- CI run: [43072854083](https://github.com/buttercode101/security-assessment-alpha-/actions/runs/43072854083) — 52/52 unit tests, live health/dashboard smoke and anonymous API lifecycle passed.
- CI status: `ci/full-validation = success`.
- Production Worker source and release gate are committed in the repository; production deployment version and bindings were independently checked through the Cloudflare API.
- Egress tests were executed using a temporary fixed-destination Worker, then that Worker and its temporary policy rules were removed.
- A successful build, screenshot or deployed version alone is not treated as proof of end-to-end behaviour.
