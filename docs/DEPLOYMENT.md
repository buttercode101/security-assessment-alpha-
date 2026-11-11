# Deployment

## Current production Worker
- Script: `security-assessment-alpha`
- URL: https://security-assessment-alpha.buttercoder-dev.workers.dev
- D1 database: `secops-platform-core`
- Binding: `DB`
- Config: `wrangler.toml`

## Manual deployment from GitHub Actions
1. In the GitHub repository, open Settings → Secrets and variables → Actions.
2. Add repository secret `CLOUDFLARE_API_TOKEN` with a token permitted to edit Workers scripts and deploy Workers.
3. Open Actions → Deploy Worker → Run workflow.
4. The workflow runs `npm test` before invoking Wrangler.
5. Confirm the new Worker version receives 100% traffic in Cloudflare and run the health/UI smoke tests.

Never commit an API token or put it in `wrangler.toml`.

## Current manual deployment path
The current version was uploaded through the connected Cloudflare account API after fetching the exact `worker.js` file from GitHub. The deployed Worker version was verified in the Cloudflare deployment list with 100% traffic.

## Important
The current production release has `SCAN_EGRESS_READY=enabled` after public HTTPS egress, private-destination rejection, DNS-to-private rejection and a controlled Gateway L4 policy A/B test. The Worker still requires a DNS-TXT-verified target, and its assessment scope remains one passive HTTPS GET with redirects disabled. Do not broaden scan scope until the remaining security-model release gates are independently validated.
