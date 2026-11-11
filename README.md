# Security Assessment Alpha

Private-alpha security configuration assessment platform. Cloudflare Workers + D1.

## Current release status

- Ownership proof: DNS TXT only.
- Active HTTP assessment: intentionally paused until isolated outbound networking and connect-time DNS-rebinding protections are proven.
- Authentication: browser-bound anonymous workspace only; not suitable as a public multi-tenant identity system.
- Scope: no exploit testing, crawling, authenticated scanning, load testing, or DDoS functionality.
- Public-IP preflight checks are conservative but incomplete and are not connect-time egress enforcement.
- Cloudflare Access/Zero Trust is not enabled on the account yet; the dedicated Gateway egress policy cannot be created until an administrator enables it in the dashboard.

## Available workspace capabilities

- Register HTTPS website targets and prove ownership with a DNS TXT record.
- Discover up to 250 subdomain names from public Certificate Transparency records after ownership verification.
- Check discovered names using Cloudflare DNS-over-HTTPS for current A/AAAA answers. This does not open an HTTP/TCP connection to the host.
- Review the latest 20 assessment records.
- Review finding evidence and remediation guidance when assessments exist.
- Remove a website and its associated findings, scans, events, and discovered-asset records from the current workspace.

Certificate Transparency discovery sends the verified hostname to crt.sh, a public third-party certificate search service. DNS checks query Cloudflare's resolver only. Historical certificate names and public DNS answers do not prove that an HTTP service is live or secure.

## Runtime status

The live health endpoint reports `mode: passive-only`, `scanner_state: paused`, and `egress: gateway-vpc` until the dedicated VPC binding and Gateway policy are configured and independently verified.

## Development

The production Worker source is `worker.js`. Database schema is in `database/schema.sql`. Security design and release gates are in `docs/`.

Do not set `SCAN_EGRESS_READY=enabled` until the dedicated `EGRESS` VPC binding and its Gateway network policy have passed real network-level tests. The Worker now requires both the release flag and the EGRESS binding, and sends target requests only through that binding.
