# Trivy API Contract (Frontend → Backend)

This is the complete list of everything the frontend expects from the Go
backend. If you build exactly this, the extension and website work against
your server with no changes needed on the frontend side.

The canonical types live in `shared/types.ts` in this repo — treat that
file as the source of truth if anything here and the code ever disagree.
The equivalent JSON is documented below so you don't need to read TypeScript
to use it.

---

## Base URL

Frontend reads the backend URL from one env var: `VITE_BACKEND_URL`
(defaults to `http://localhost:8080` for local dev — see `.env.example`).
All endpoints below are relative to that base URL.

---

## Who calls this

Both the browser extension and the website dashboard call `POST
/api/v1/scans` directly — the dashboard doesn't have its own separate
endpoint. On the dashboard, the person types in a target URL and the page
calls this same endpoint itself (there's no "current tab" to read on a
website, so the target has to be entered manually). Keep the CORS note
below in mind: the dashboard's calls go through normal browser CORS,
unlike the extension's.

## Endpoints

### `GET /api/v1/health`

Used by the popup before an active/combined scan to confirm the backend is
up. Return `200 OK` with any body (or empty) if healthy. Any non-2xx status
is treated as "backend unreachable" by the frontend.

### `POST /api/v1/scans`

The main endpoint. Frontend sends passive findings it already computed in
the browser, plus scan mode and consent. If mode is `active` or `combined`,
the backend runs the active probe engine (reflected input marker, SQL
injection probe, CORS test) and returns the combined findings list.

**Request body:**

```json
{
  "target": "https://example-shop.com/",
  "scanMode": "combined",
  "consent": true,
  "findings": [
    {
      "category": "header",
      "pageUrl": "https://example-shop.com/",
      "header": "content-security-policy",
      "value": null,
      "status": "missing",
      "severity": "Medium"
    },
    {
      "category": "insecure_form",
      "pageUrl": "https://example-shop.com/login",
      "formAction": "http://example-shop.com/login",
      "method": "POST",
      "hasPasswordField": true,
      "isActionInsecure": true,
      "autocompleteOnSensitive": false,
      "hasCsrfToken": false,
      "severity": "Medium"
    }
  ],
  "rateLimit": {
    "requestsPerSecond": 3,
    "maxConcurrency": 2
  },
  "excludedPaths": ["/logout", "/delete", "/checkout"]
}
```

`rateLimit` and `excludedPaths` are only present on `active`/`combined` requests — they come from the person's options-page settings and are absent on passive scans. Honor `excludedPaths` server-side even though the frontend also checks it client-side first (defense in depth, not a substitute for backend enforcement).

**Rules to enforce server-side:**

- Reject the request with `400` if `scanMode` is `"active"` or `"combined"`
  and `consent` is not exactly `true`. This is the consent gate from the
  report — do not let a missing or falsy consent field slip through.
- `findings` is always an array, possibly empty (e.g. a passive scan on a
  page with zero issues found).

**Response body:**

```json
{
  "findings": [
    { "...same finding objects as above, echoed back or extended..." }
  ],
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 0
  }
}
```

`summary` is optional — if you don't want to compute it server-side, omit
it and the frontend will derive counts from the findings array itself.

### `GET /api/v1/scans/{scan_id}` (not wired up yet — open question)

The frontend has a client function ready for this (`getScanResult` in
`shared/api-client.ts`) but it's currently unused. This only matters if you
want `POST /api/v1/scans` to return immediately with a `scan_id` while the
active probes run asynchronously, and have the frontend poll this endpoint
for the result. If instead `POST /api/v1/scans` just blocks and returns the
full result synchronously (simpler, fine for a small number of active
checks), this endpoint isn't needed at all. **Decide this together before
building it** — don't build async polling unless you actually need it.

---

## Auth

`submitScan()` accepts an optional bearer token and sends it as
`Authorization: Bearer <token>` if provided. Whether you require this is
up to you — the frontend already supports sending it, it just isn't wired
to a login flow yet. Tell us if/when you want that connected.

---

## Storage

**Still undecided — do not build around either assumption yet.** The
report currently describes PostgreSQL persistence, but we're not sure yet
whether we want scan history, a single overwritten "latest scan per
target," or no persistence at all. Whatever you build, keep the `POST
/api/v1/scans` request/response shape above unchanged — that contract is
stable regardless of what you do with the data after generating the
response.

---

## Per-category notes (validate / process / store)

| Category | Backend should validate | Backend should recompute | Storage note |
|---|---|---|---|
| `header` | `header` is a known name; `status` is one of `missing`/`weak`/`ok` | Nothing — frontend logic is authoritative here | Not sensitive |
| `insecure_form` | `formAction` is a valid URL; booleans are real booleans | Recommend recomputing severity server-side rather than trusting the client | Store URL only, never form field contents |
| `unencrypted_credentials` | `hasPasswordField` and `isHttp` are both `true` | Always treat as High/Critical — never accept a lower severity from the client | Store URL only |
| `mixed_content` | `resourceUrl` is HTTP, `pageUrl` is HTTPS | Recompute severity from `resourceType` (script/iframe = High, else Low) | Dedupe repeated resource URLs |
| `sensitive_url` | The `url` field looks genuinely redacted (contains `***`, not a raw value) | N/A | Never log the raw request body if a value looks unredacted — reject instead |
| active-scan categories (`reflected_input`, `sql_injection`, `cors_misconfig`) | N/A — backend produces these itself | N/A | These only exist if the backend generated them |

---

## CORS

- **Extension → backend:** no CORS handling needed on your end. The
  extension's background worker has `host_permissions: ["<all_urls>"]`
  declared in its manifest, which exempts it from browser CORS enforcement.
- **Website dashboard → backend:** this **does** go through normal browser
  CORS rules, since it's a regular web page making fetch calls. You'll need
  to set `Access-Control-Allow-Origin` for whatever domain the dashboard is
  served from (e.g. `https://app.trivy.io` or `http://localhost:5173` in
  dev).

---

## Error format

Frontend currently just checks `res.ok` and reads the response body as
text for the error message. A JSON error body like the below is fine and
will display cleanly, but isn't required yet:

```json
{ "error": "consent is required for active or combined scans" }
```
