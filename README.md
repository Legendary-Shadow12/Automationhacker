# Relay Automation Studio

Relay is an original workflow automation app inspired by visual automation tools. This repository now contains a self-hosted local runtime, a persistent workspace API, a node editor, execution history, webhook entry points, and a simple scheduler.

## Start

Requires Node.js 18 or newer. From this folder:

```powershell
node server.mjs
```

Open <http://127.0.0.1:4173>. The server creates `data/relay.json` on first start and stores the local workspace there. Back up this file before upgrades. Set `PORT` to change the port. `HOST` defaults to `127.0.0.1`; do not expose this local build directly to the internet.

## What works

- Persistent workflow, credential, and execution state through a same-origin JSON API.
- Create workflows from scratch or from the included templates; rename, activate, pause, edit, drag, add, and remove nodes.
- Manual workflow runs with step-level execution records and JSON input/output metadata.
- Webhook triggers: activate a workflow with a Webhook node, then `POST` JSON to `http://127.0.0.1:4173/webhooks/<workflow-id>`.
- A local schedule poller for active Schedule nodes, including weekday time strings such as `Mon–Fri · 09:00` and `every minute`.
- If-condition and Set-fields nodes, a bounded Wait node, searchable run history, and execution detail logs.
- HTTP Request nodes for public HTTPS endpoints, with optional Bearer-token credentials. Private/reserved IP addresses, redirects, and oversized responses are blocked.
- Slack incoming webhooks and SendGrid email actions when their matching credentials are connected. Set `RELAY_FROM_EMAIL` to a verified sender for SendGrid.
- Credential secrets encrypted on the local server using AES-256-GCM; the key is saved separately with restrictive file permissions where supported. Back up `data/master.key` securely with `data/relay.json` if you need to preserve credential access.
- A workspace overview, workflows, credentials, templates, executions, and settings screens.

Example webhook request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:4173/webhooks/wf-1 -ContentType 'application/json' -Body '{"score":72,"email":"alex@example.com"}'
```

## Limits of this build

This is a single-workspace local build, not the public multi-user SaaS or full n8n feature set. It has no authentication, enforced roles, organization isolation, billing, distributed workers, workflow versioning, OAuth, or broad integration catalog. Slack incoming webhooks and SendGrid are basic connector implementations; other unconfigured provider nodes are recorded as skipped. The scheduler runs in the web server process and is intended for local use only. Credential secrets are encrypted at rest and used by supported nodes.

The production direction from the interview is a Vue 3/TypeScript editor and Node.js/TypeScript API, PostgreSQL tenant data, encrypted credentials, and Redis-backed workers. This build uses browser-native JavaScript and a dependency-free Node server so it can run in the current workspace without package installation. Production SaaS deployment needs HTTPS, authentication, tenant isolation, secret management, outbound request protections, worker isolation, rate limits, and operational monitoring before public access.
