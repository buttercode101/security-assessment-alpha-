# Security Assessment Alpha

Private-alpha security configuration assessment platform. Cloudflare Workers + D1.

## Current release status

- Ownership proof: DNS TXT only.
- Active HTTP assessment: intentionally paused until live Gateway policy enforcement and connect-time DNS-rebinding protections are proven.
- Authentication: browser-bound anonymous workspace only; not suitable as a public multi-tenant identity system.
- Scope: no exploit testing, crawling, authenticated scanning, load testing, or DDoS functionality.
- Public-IP preflight checks are conservative but incomplete and are not connect-time egress enforcement.
- Cloudflare Access/Zero Trust is enabled. A dedicated scanner VNet is configured as the account default network, an L4 Gateway block policy is scoped to it, and the production Worker has an `EGRESS` VPC binding. These settings are API-verified.
- Live runtime probes confirmed public HTTPS egress (`https://example.com/` returned HTTP 200). Direct loopback/private IPv4, IPv6 loopback/ULA/link-local, and hostnames resolving to private IPv4 returned `ProxyError: destination_ip_prohibited`. The IPv4 link-local probe timed out and is inconclusive.
- **Gateway policy attribution is not yet proven.** Temporary narrow Gateway test rules did not block their known-public test destinations. The runtime rejections may be enforced by the Workers egress layer rather than the configured Gateway L4 rule. Gateway activity logs and policy matching still require verification.
- The Cloudflare account currently has no Tunnels or Mesh nodes listed. Do not infer private-network connectivity from the VPC binding alone.

## Available workspace capabilities

- Register HTTPS website targets and prove ownership with a DNS TXT record.
- Discover up to 250 subdomain names from public Certificate Transparency records after ownership verification.
- Check discovered names using Cloudflare DNS-over-HTTPS for current A/AAAA answers. This does not open an HTTP/TCP connection to the host.
- Review the latest 20 assessment records.
- Review finding evidence and remediation guidance when assessments exist.
- Remove a website and its associated findings, scans, events, and discovered-asset records from the current workspace.

Certificate Transparency discovery sends the verified hostname to crt.sh, a public third-party certificate search service. DNS checks query Cloudflare's resolver only. Historical certificate names and public DNS answers do not prove that an HTTP service is live or secure.

## Runtime status

The live health endpoint should report `mode: passive-only`, `scanner_state: paused`, and `egress: gateway-vpc` until Gateway policy enforcement and connect-time destination controls pass independent tests.

## Development

The production Worker source is `worker.js`. Database schema is in `database/schema.sql`. Security design and release gates are in `docs/`.

Do not set `SCAN_EGRESS_READY=enabled` until public HTTPS, private IPv4/IPv6 blocking, private DNS destination blocking, IPv4 link-local behavior, and Gateway policy attribution have passed. The Worker requires both the release flag and the EGRESS binding, and sends target requests only through that binding.
