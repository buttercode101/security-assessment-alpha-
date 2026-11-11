# Security Assessment Alpha

Private-alpha security configuration assessment platform. Cloudflare Workers + D1.

## Current release status

- Ownership proof: DNS TXT only.
- Scanning: intentionally paused behind the `SCAN_EGRESS_READY` feature gate until isolated outbound networking and DNS-rebinding protections are proven.
- Authentication: browser-bound anonymous workspace only; not suitable for public multi-tenant launch.
- Scope: no exploit testing, crawling, authenticated scanning, load testing, or DDoS functionality.
- Network preflight rejects malformed IP literals and common non-public IPv4/IPv6 ranges, but this is not a complete address registry or connect-time egress control.

## Development

The production Worker source is `worker.js`. Database schema is in `database/schema.sql`. Security design and release gates are in `docs/`.

Do not enable scanning by setting `SCAN_EGRESS_READY` until the security release gates are met and verified in a dedicated isolated scanner environment.
