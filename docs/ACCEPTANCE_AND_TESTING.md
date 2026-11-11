# Alpha acceptance and verification plan

## Current acceptance
- [x] Cloudflare Worker deployed; D1 binding present.
- [x] D1 tables created and schema captured.
- [x] Workspace cookie is Secure, HttpOnly, SameSite=Strict.
- [x] Ownership verification requires DNS TXT.
- [x] Exact Origin required for non-GET API routes.
- [x] Scan API is closed behind SCAN_EGRESS_READY.
- [x] UI explains assessments are paused.
- [ ] Live browser smoke test from an external client.
- [ ] Verify add-target and ownership TXT flow against a controlled test domain.
- [ ] Verify cross-workspace object access is denied.
- [ ] Verify scan endpoint returns 503 while feature gate is unset.
- [ ] Independent CSP and responsive-layout review on 320, 360, 375, 768, 1024 and 1440 px.
- [ ] Keyboard-only and screen-reader pass.
- [ ] Browser console/network error-free pass.

## Required test matrix
| Area | Cases | Expected |
|---|---|---|
| URL intake | http, credentials, IP literal, localhost, private suffix, non-443 port | Rejected |
| Ownership | correct TXT, absent TXT, wrong TXT, DNS timeout | Only exact TXT succeeds |
| Sessions | no cookie, valid cookie, invalid cookie, cookie theft assumptions | 401 or isolated workspace |
| CSRF | missing Origin, foreign Origin, exact Origin | Reject, reject, accept |
| Tenant isolation | target/scan/finding IDs from another workspace | 404/denied |
| Scan gate | unset flag, false, true | 503, 503, still blocked pending isolated runner |
| Abuse | target quota, rapid retries, request floods | bounded and logged |
| SSRF | RFC1918, loopback, link-local, CGNAT, IPv6 local, mixed DNS, CNAME rebinding | blocked at connect-time |
| UI | 320/360/375/768/1024/1440 widths, long domains, errors, empty/loading states | no overflow or broken controls |
| Accessibility | keyboard, focus, contrast, labels, reduced motion | WCAG 2.2 AA target |

## Evidence standard
A checkbox is only complete when a test result, command, timestamp and environment are recorded. A deployed version or a successful build alone is not proof of end-to-end behaviour.
