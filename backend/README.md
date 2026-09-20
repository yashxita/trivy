# Trivy backend

This is the local/private Go API used by the browser extension and website.
The API runs synchronously and stores sanitized results in PostgreSQL for seven
days. Active scans require explicit consent and perform a bounded, same-origin
crawl with non-destructive HTTP checks.

## Run with Docker

```sh
docker compose -f compose.yml up --build
```

The API is available at `http://localhost:8080`. The frontend remains a host
process; set `VITE_BACKEND_URL=http://localhost:8080` when running it.

## Run directly

Start PostgreSQL, copy `.env.example` to `.env`, export the values, then run:

```sh
go run ./cmd/server
```

## Endpoints

- `GET /api/v1/health`
- `POST /api/v1/scans`
- `GET /api/v1/scans/{scanId}`

The request and finding schemas are documented in
`../frontend/extension/API_CONTRACT.md`.

## Active scan behavior

Active scans discover same-origin links, GET/POST forms, scripts, and likely API
routes referenced by JavaScript. On an explicitly allowlisted target they also
submit bounded invalid form/JSON canaries to check body-parameter reflection and
database-error signatures. GET and body parameters are tested with contextual
reflected-input checks, quote probes, and boolean response differentials for
possible SQL injection. Reflected-input markers contain inert delimiter
characters but no executable script. Successful logins, authentication bypasses,
time-delay payloads, and state-changing workflows are never intentionally
attempted.

Active requests are restricted to hosts in `TRIVY_INTRUSIVE_ALLOWED_HOSTS`.
The Compose lab exposes the local Juice Shop as `juice-shop.localhost:3000`;
use the `lab` profile for local testing. Public targets are not allowlisted by
default.

Responses include a `coverage` object with discovered/scanned page counts,
requests made, forms found, parameters tested, truncation state, and warnings.
Server-enforced page, depth, request, response-size, duration, rate, concurrency,
excluded-path, same-origin, redirect, and SSRF limits apply to every scan.
