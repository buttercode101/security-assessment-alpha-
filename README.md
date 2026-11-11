# Security Assessment Alpha

Private-alpha security configuration assessment platform. Cloudflare Workers + D1.

## Current release status

- Ownership proof: DNS TXT only.
- Active HTTP assessment: intentionally paused until isolated outbound networking and connect-time DNS-rebinding protections are proven.
- Authentication: browser-bound anonymous workspace only; not suitable as a public multi-tenant identity system.
- Scope: no exploit testing, crawling, authenticated scanning, load testing, or DDoS functionality.
- Public-IP preflight checks are conservative but incomplete and are not connect-time egress enforcement.

## Available workspace capabilities

- Register HTTPS website targets and prove ownership with a DNS TXT record.
- Discover up to 250 subdomain names from public Certificate Transparency records after ownership verification.
- Check discovered names using Cloudflare DNS-over-HTTPS for current A/AAAA answers. This does not open an HTTP/TCP connection to the host.
- Review the latest 20 assessment records.
- Review finding evidence and remediation guidance when assessments exist.
- Remove a website and its associated findings, scans, events, and discovered-asset records from the current workspace.

Certificate Transparency discovery sends the verified hostname to crt.sh, a public third-party certificate search service. DNS checks query Cloudflare's resolver only. Historical certificate names and public DNS answers do not prove that an HTTP service is live or secure.

## Development

The production Worker source is `worker.js`. Database schema is in `database/schema.sql`. Security design and release gates are in `docs/`.

Do not enable scanning by setting `SCAN_EGRESS_READY`. Worker environment variables are strings while the current deployed gate requires the boolean `true`, so it intentionally fails closed. Replace it with a verified scanner service binding only after the isolated scanner has passed all release gates. Cloudflare Sandboxes/Containers require a Workers Paid plan; confirm account entitlement and cost before provisioning.
