# API Reference

This document covers the current `nss-quarry` HTTP API as implemented in the repository today.

It is written for operators, integrators, and helpdesk tooling that need to:
- authenticate to `nss-quarry`
- query Parquet-backed NSS data
- export results
- analyze `.pcap` and `.pcapng` files
- read dashboard aggregates
- manage admin-only controls such as visibility filters, audit export, and ingestor file finalization

## Base URL

Typical production-style URL:

```text
https://nss-quarry.example.com
```

Lab example with a self-signed certificate:

```text
https://192.168.178.63
```

## Authentication Model

`nss-quarry` uses a session cookie, not a bearer token.

Authenticated routes require that your HTTP client keeps the session cookie returned by:
- `POST /auth/login` in `local_users` mode
- `GET /auth/callback` in OIDC modes after browser login completes

Supported auth modes:
- `local_users`
- `oidc_entra`
- `oidc_okta`

Automation auth:
- optional API tokens can be configured in `auth.api_tokens.tokens`
- API clients can authenticate with either:
  - `Authorization: Bearer <token>`
  - `X-API-Token: <token>`
- API-token auth is intended for non-browser integrations such as ServiceNow workflows
- API tokens can be restricted to specific source IPs or CIDR ranges
- API tokens can be disabled at runtime by an admin without restarting the service

Role levels:
- `helpdesk`
- `analyst`
- `admin`

Role behavior:
- `helpdesk` can search, export, inspect schema, load dashboards, and run PCAP Assist, but sensitive fields may be redacted.
- `analyst` can use the same query APIs without helpdesk redaction.
- `admin` can also read audit logs, change visibility filters, and trigger ingestor finalization.

Operational note:
- session state is held in-memory by `nss-quarry`
- a service restart invalidates existing sessions
- API tokens are config-backed and survive service restarts
- bootstrap tokens from `auth.api_tokens.tokens` are seeded into the managed token store on first run

## Common Python Setup

Examples below use `requests`.

Install dependency:

```bash
python3 -m pip install requests
```

Suggested Python bootstrap:

```python
import json
from pathlib import Path

import requests
import urllib3

BASE_URL = "https://nss-quarry.example.com"

# Preferred in production:
# VERIFY_TLS = "/etc/pki/ca-trust/source/anchors/nss-quarry-ca.pem"
#
# Lab/self-signed shortcut only:
VERIFY_TLS = False

if VERIFY_TLS is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = VERIFY_TLS


def require_ok(response: requests.Response) -> requests.Response:
    if not response.ok:
        raise RuntimeError(
            f"{response.request.method} {response.url} failed: "
            f"{response.status_code} {response.text}"
        )
    return response


def pretty(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))
```

Example bearer-token bootstrap for automation:

```python
API_TOKEN = "paste-generated-token-here"

session = requests.Session()
session.verify = VERIFY_TLS
session.headers.update({
    "Authorization": f"Bearer {API_TOKEN}",
})
```

Equivalent custom header:

```python
session.headers.update({
    "X-API-Token": API_TOKEN,
})
```

Error format for application errors:

```json
{
  "error": "authentication required"
}
```

Typical error status codes:
- `400` bad request or validation failure
- `401` no valid session
- `403` role too low
- `405` wrong auth mode for endpoint
- `502` upstream ingestor call failed

## Endpoint Summary

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | basic liveness |
| `GET` | `/readyz` | none | readiness against Parquet availability |
| `GET` | `/dashboard` | none | HTML dashboard page |
| `GET` | `/assets/world.geojson` | none | bundled world map asset |
| `GET` | `/auth/login` | none | start OIDC login flow |
| `POST` | `/auth/login` | none | local user login |
| `GET` | `/auth/callback` | none | OIDC callback endpoint |
| `POST` | `/auth/logout` | optional session | end session |
| `GET` | `/api/me` | `helpdesk+` | current authenticated user |
| `GET` | `/authz/ingestor` | `admin` | admin gate check used for ingestor UI |
| `POST` | `/api/search` | `helpdesk+` | search logs |
| `POST` | `/api/export/csv` | `helpdesk+` | export search results as CSV |
| `POST` | `/api/pcap/analyze` | `helpdesk+` | analyze `.pcap` or `.pcapng` |
| `GET` | `/api/dashboards/{name}` | `helpdesk+` | 24h dashboard aggregate payload |
| `GET` | `/api/schema` | `helpdesk+` | schema mapping and detected parquet columns |
| `GET` | `/api/admin/api-tokens` | `admin` | list managed API tokens |
| `POST` | `/api/admin/api-tokens` | `admin` | create a managed API token |
| `PUT` | `/api/admin/api-tokens/{name}` | `admin` | update role, source allowlist, or enabled state |
| `GET` | `/api/admin/visibility-filters` | `admin` | read hidden URL/IP rules |
| `PUT` | `/api/admin/visibility-filters` | `admin` | update hidden URL/IP rules |
| `GET` | `/api/audit` | `admin` | list audit events |
| `GET` | `/api/audit/export/csv` | `admin` | export filtered audit events |
| `POST` | `/api/admin/ingestor/force-finalize-open-files` | `admin` | finalize non-empty active parquet writers in `nss-ingestor` |

## Public Endpoints

### `GET /healthz`

Returns service liveness.

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/healthz"))
pretty(response.json())
```

Example response:

```json
{
  "generated_at": "2026-04-04T21:20:11.201473Z",
  "status": "ok"
}
```

### `GET /readyz`

Checks that the configured Parquet root is queryable and contains data.

Python:

```python
response = session.get(f"{BASE_URL}/readyz")
print(response.status_code)
pretty(response.json())
```

If ready:

```json
{
  "generated_at": "2026-04-04T21:20:29.654782Z",
  "reason": null,
  "status": "ok"
}
```

If degraded:

```json
{
  "generated_at": "2026-04-04T21:20:29.654782Z",
  "reason": "no parquet files found under configured parquet_root",
  "status": "degraded"
}
```

### `GET /dashboard`

Returns the frontend HTML page.

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/dashboard"))
print(response.headers["content-type"])
print(response.text[:200])
```

### `GET /assets/world.geojson`

Returns the built-in world map asset used by the dashboard.

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/assets/world.geojson"))
geojson = response.json()
print(geojson["type"])
print(len(geojson["features"]))
```

## Authentication Endpoints

### `POST /auth/login`

Local-user login. This works only when `auth.mode = "local_users"`.

Request body:

```json
{
  "username": "admin",
  "password": "admin"
}
```

Python:

```python
payload = {
    "username": "admin",
    "password": "admin",
}
response = require_ok(session.post(f"{BASE_URL}/auth/login", json=payload))
pretty(response.json())
```

Example response:

```json
{
  "user": {
    "auth_mode": "local_users",
    "role": "admin",
    "username": "admin"
  }
}
```

Notes:
- the session cookie is returned in `Set-Cookie`
- `requests.Session()` stores it automatically
- in OIDC modes this endpoint returns `400` or `405` depending on call path and config

### `GET /auth/login`

Starts the OIDC login flow. This works only in `oidc_entra` or `oidc_okta` mode.

Python:

```python
response = session.get(
    f"{BASE_URL}/auth/login",
    allow_redirects=False,
)
print(response.status_code)
print(response.headers.get("Location"))
```

Expected behavior:
- returns a redirect to the IdP authorization URL
- browser-based login should follow this redirect

Note:
- this route is intended for interactive browser login, not headless service-to-service auth

### `GET /auth/callback`

OIDC callback endpoint used by the identity provider after login.

Query parameters:
- `code`
- `state`

This is normally not called directly from automation. The IdP redirects the user browser here, `nss-quarry` validates the callback, sets the session cookie, and redirects to `/dashboard`.

### `GET /api/me`

Returns the currently authenticated user and role.

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/api/me"))
pretty(response.json())
```

If the request used an API token, `auth_mode` is returned as `api_token`.

### `POST /auth/logout`

Clears the current session.

Behavior:
- returns `204` even if no session is currently present
- clears the cookie if one exists

Python:

```python
response = require_ok(session.post(f"{BASE_URL}/auth/logout"))
print(response.status_code)  # 204
```

## Search and Query APIs

### `POST /api/search`

Queries NSS data from Parquet and returns JSON rows.

Request fields:
- `time_from`: RFC3339 timestamp
- `time_to`: RFC3339 timestamp
- `filters`: optional filter object
- `limit`: optional row limit
- `columns`: optional list of column names to return

Filter object keys:
- `user`
- `url`
- `action`
- `response_code` or alias `respcode`
- `reason`
- `threat`
- `category`
- `source_ip` or alias `cip`
- `server_ip` or alias `sip`
- `device`
- `department`

Filter semantics:
- `user`, `url`, `action`, `reason`, `threat`, `category`, `device`, `department`: case-insensitive substring match
- `response_code`: substring match for one value, exact OR match for comma-separated values
- `source_ip`: substring match for one value, exact OR match for comma-separated values
- `server_ip`: exact OR match for comma-separated values

Limits and behavior:
- request range must not exceed `query.max_days_per_query`
- returned rows are sorted by time descending
- `limit` is capped by `query.max_rows`
- only hourly Parquet partitions that overlap the requested time range are read
- helpdesk users receive configured field masking
- admin visibility filters remove matching rows after query execution

Python:

```python
payload = {
    "time_from": "2026-04-04T18:55:00Z",
    "time_to": "2026-04-04T19:10:00Z",
    "filters": {
        "action": "Blocked",
        "server_ip": "1.1.1.1,8.8.8.8",
        "reason": "Not allowed to browse this category",
    },
    "limit": 100,
    "columns": [
        "time",
        "action",
        "respcode",
        "reason",
        "sip",
        "cip",
        "url",
        "urlcat",
        "devicehostname",
        "dept",
    ],
}

response = require_ok(session.post(f"{BASE_URL}/api/search", json=payload))
pretty(response.json())
```

Example response:

```json
{
  "row_count": 2,
  "rows": [
    {
      "action": "Blocked",
      "cip": "192.168.10.44",
      "dept": "Finance",
      "devicehostname": "WS-FIN-1044",
      "reason": "Not allowed to browse this category",
      "respcode": "403",
      "sip": "8.8.8.8",
      "time": "2026-04-04 19:03:44",
      "url": "example.badsite.test/path",
      "urlcat": "Security"
    }
  ],
  "truncated": false
}
```

### `POST /api/export/csv`

Runs the same search request as `/api/search` but returns CSV.

Python:

```python
payload = {
    "time_from": "2026-04-04T18:00:00Z",
    "time_to": "2026-04-04T19:00:00Z",
    "filters": {
        "action": "Blocked",
        "response_code": "403",
    },
    "limit": 500,
    "columns": ["time", "action", "respcode", "reason", "sip", "url"],
}

response = require_ok(session.post(f"{BASE_URL}/api/export/csv", json=payload))
Path("nss-quarry-export.csv").write_bytes(response.content)
print("saved", len(response.content), "bytes")
```

Response headers:
- `Content-Type: text/csv; charset=utf-8`
- `Content-Disposition: attachment; filename="nss-quarry-export.csv"`

### `POST /api/pcap/analyze`

Analyzes `.pcap` or `.pcapng`, extracts time range and IPs, and returns a padded search window.

Multipart fields:
- `pcap`: required file upload
- `max_ips`: optional integer, clamped to `1..5000`, default `500`

Current limits:
- max upload size: `5 GiB`
- search window padding: `-5 minutes` before capture start and `+5 minutes` after capture end

Python:

```python
pcap_path = Path("incident.pcapng")
with pcap_path.open("rb") as handle:
    response = require_ok(
        session.post(
            f"{BASE_URL}/api/pcap/analyze",
            files={"pcap": (pcap_path.name, handle, "application/octet-stream")},
            data={"max_ips": "1000"},
        )
    )

result = response.json()
pretty(result)
```

Useful response fields:
- `time_from`
- `time_to`
- `search_time_from`
- `search_time_to`
- `packet_count`
- `source_ips`
- `destination_ips`
- `truncated_source_ips`
- `truncated_ips`

Example follow-up search using the returned time window and destination IP list:

```python
with open("incident.pcapng", "rb") as handle:
    analysis = require_ok(
        session.post(
            f"{BASE_URL}/api/pcap/analyze",
            files={"pcap": ("incident.pcapng", handle, "application/octet-stream")},
        )
    ).json()

search_payload = {
    "time_from": analysis["search_time_from"],
    "time_to": analysis["search_time_to"],
    "filters": {
        "server_ip": ",".join(analysis["destination_ips"]),
        "source_ip": ",".join(analysis["source_ips"]),
    },
    "limit": 500,
    "columns": ["time", "action", "reason", "respcode", "cip", "sip", "url"],
}

response = require_ok(session.post(f"{BASE_URL}/api/search", json=search_payload))
pretty(response.json())
```

### `GET /api/dashboards/{name}`

Returns dashboard cards and tables from the persisted hourly overview snapshot.

Use `overview` as the dashboard name.

Current implementation note:
- the backend currently returns the same 24h overview payload regardless of `{name}`
- clients should still use `overview` for forward compatibility
- the default response is snapshot-backed and avoids a live full 24-hour parquet scan on every request
- use `refresh=delta` to merge newer finalized parquet data on top of the latest hourly snapshot

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/api/dashboards/overview"))
pretty(response.json())
```

Manual delta refresh:

```python
response = require_ok(
    session.get(f"{BASE_URL}/api/dashboards/overview", params={"refresh": "delta"})
)
pretty(response.json())
```

Response includes:
- cards:
  - `events_24h`
  - `blocked_24h`
  - `threat_hits_24h`
- tables:
  - `top_users`
  - `top_categories`
  - `top_devices`
  - `top_source_ips`
  - `top_departments`
  - `top_response_codes`
  - `country_flows_24h`
- freshness metadata:
  - `source`
  - `snapshot_generated_at`
  - `data_window_from`
  - `data_window_to`
  - `refresh_in_progress`
  - `notes`

### `GET /api/schema`

Returns:
- active logical field mapping
- detected Parquet columns from a sample Parquet file
- default query columns
- helpdesk mask fields
- auth mode

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/api/schema"))
schema = response.json()
pretty(schema)
```

Useful fields:
- `auth_mode`
- `fields`
- `parquet_columns`
- `parquet_schema_error`
- `default_columns`
- `helpdesk_mask_fields`

If the request used an API token, `auth_mode` is returned as `api_token`.

If an API token is presented from a source outside its allowlist, the API returns:

```json
{
  "error": "api token source is not allowed"
}
```

## Admin APIs

### `GET /api/admin/api-tokens`

Returns token metadata without exposing token hashes or plaintext tokens.

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/api/admin/api-tokens"))
pretty(response.json())
```

### `POST /api/admin/api-tokens`

Creates a new API token and returns the plaintext token once.

Request body:

```json
{
  "name": "svc-servicenow-analyst",
  "role": "analyst",
  "allowed_sources": [
    "10.0.0.0/24",
    "192.168.1.10"
  ]
}
```

Python:

```python
payload = {
    "name": "svc-servicenow-analyst",
    "role": "analyst",
    "allowed_sources": ["10.0.0.0/24", "192.168.1.10"],
}
response = require_ok(session.post(f"{BASE_URL}/api/admin/api-tokens", json=payload))
created = response.json()
pretty(created["token_info"])
print("copy token now:", created["token"])
```

Notes:
- the plaintext token is shown only in this create response
- the server stores only the Argon2 hash
- source entries can be a single IP or a CIDR range

### `PUT /api/admin/api-tokens/{name}`

Updates an existing token’s role, source allowlist, or enabled state.

Request body:

```json
{
  "role": "analyst",
  "allowed_sources": [
    "10.0.0.0/24"
  ],
  "disabled": true
}
```

Python:

```python
payload = {
    "role": "analyst",
    "allowed_sources": ["10.0.0.0/24"],
    "disabled": True,
}
response = require_ok(
    session.put(f"{BASE_URL}/api/admin/api-tokens/svc-servicenow-analyst", json=payload)
)
pretty(response.json())
```

### `GET /authz/ingestor`

This is a small admin gate check used by the UI before showing ingestor controls.

Python:

```python
response = session.get(f"{BASE_URL}/authz/ingestor")
print(response.status_code)
```

Status behavior:
- `204` admin session is allowed
- `401` no session
- `403` not admin

### `GET /api/admin/visibility-filters`

Returns admin-managed row hiding rules.

Rules are applied to search and dashboard results after query execution.

Supported rule types:
- `url_regex`: regex match against URL-like fields
- `blocked_ips`: exact IP matches against source/server IP-related fields

Python:

```python
response = require_ok(session.get(f"{BASE_URL}/api/admin/visibility-filters"))
pretty(response.json())
```

Example response:

```json
{
  "blocked_ips": [
    "203.0.113.10"
  ],
  "url_regex": [
    "^internal\\.example\\.com/",
    "secret-app"
  ]
}
```

### `PUT /api/admin/visibility-filters`

Replaces the current visibility filters and persists them to disk.

Python:

```python
payload = {
    "url_regex": [
        "^internal\\.example\\.com/",
        "admin-portal",
    ],
    "blocked_ips": [
        "203.0.113.10",
        "2001:db8::10",
    ],
}

response = require_ok(
    session.put(f"{BASE_URL}/api/admin/visibility-filters", json=payload)
)
pretty(response.json())
```

Validation notes:
- max `500` regex rules
- max `500` blocked IP rules
- each rule max length `256`
- blocked IPs must parse as real IPv4 or IPv6 addresses

### `GET /api/audit`

Returns paginated audit events.

Query parameters:
- `page`: default `1`
- `page_size`: default `50`, max `500`
- `from`: optional RFC3339
- `to`: optional RFC3339
- `actor`
- `action`
- `outcome`
- `text`

Filter semantics:
- case-insensitive contains matching
- `text` searches timestamp, actor, role, action, outcome, and metadata text

Python:

```python
params = {
    "page": 1,
    "page_size": 50,
    "from": "2026-04-04T00:00:00Z",
    "to": "2026-04-04T23:59:59Z",
    "action": "query.search",
    "actor": "admin",
}

response = require_ok(session.get(f"{BASE_URL}/api/audit", params=params))
pretty(response.json())
```

Example response shape:

```json
{
  "page": 1,
  "page_size": 50,
  "rows": [
    {
      "action": "query.search",
      "actor": "admin",
      "at": "2026-04-04T21:12:10.220315Z",
      "metadata": {
        "query": {
          "columns": [
            "time",
            "action",
            "sip"
          ],
          "filters": {
            "action": "Blocked"
          },
          "limit": 100,
          "time_from": "2026-04-04T18:00:00Z",
          "time_to": "2026-04-04T19:00:00Z"
        },
        "rows": 12
      },
      "outcome": "success",
      "role": "admin"
    }
  ],
  "total": 1,
  "total_pages": 1
}
```

### `GET /api/audit/export/csv`

Exports filtered audit rows as CSV.

Notes:
- filters are the same as `/api/audit`
- export is capped at `50,000` rows

Python:

```python
params = {
    "from": "2026-04-04T00:00:00Z",
    "to": "2026-04-04T23:59:59Z",
    "action": "admin.visibility_filters.update",
}

response = require_ok(session.get(f"{BASE_URL}/api/audit/export/csv", params=params))
Path("nss-quarry-audit.csv").write_bytes(response.content)
print("saved", len(response.content), "bytes")
```

### `POST /api/admin/ingestor/force-finalize-open-files`

Calls the local `nss-ingestor` admin API to finalize non-empty active writers.

Guardrails enforced upstream by `nss-ingestor`:
- admin-only through `nss-quarry`
- cooldown/rate limit
- only non-empty active writers are finalized
- action is audit logged with user, time, and source IP

Python:

```python
response = session.post(f"{BASE_URL}/api/admin/ingestor/force-finalize-open-files")
print(response.status_code)
pretty(response.json())
```

Example success response:

```json
{
  "cooldown_secs": 60,
  "message": "force finalized open parquet files",
  "result": {
    "finalized_files": 3,
    "finalized_rows": 185443,
    "skipped_empty_writers": 1
  },
  "retry_after_secs": null,
  "status": "ok",
  "triggered_at": "2026-04-04T21:18:42Z"
}
```

If the cooldown is still active, expect an upstream non-2xx response with payload similar to:

```json
{
  "cooldown_secs": 60,
  "message": "force finalize is cooling down",
  "retry_after_secs": 22,
  "status": "cooldown",
  "triggered_at": "2026-04-04T21:19:04Z"
}
```

## End-to-End Python Example

This example logs in, checks the current user, analyzes a PCAP, and searches logs around the captured window.

```python
from pathlib import Path

import requests
import urllib3

BASE_URL = "https://nss-quarry.example.com"
VERIFY_TLS = False

if VERIFY_TLS is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = VERIFY_TLS


def require_ok(response):
    if not response.ok:
        raise RuntimeError(f"{response.status_code} {response.text}")
    return response


require_ok(
    session.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "admin"},
    )
)

me = require_ok(session.get(f"{BASE_URL}/api/me")).json()
print("logged in as", me["user"]["username"], "role", me["user"]["role"])

pcap_file = Path("incident.pcapng")
with pcap_file.open("rb") as handle:
    analysis = require_ok(
        session.post(
            f"{BASE_URL}/api/pcap/analyze",
            files={"pcap": (pcap_file.name, handle, "application/octet-stream")},
            data={"max_ips": "500"},
        )
    ).json()

payload = {
    "time_from": analysis["search_time_from"],
    "time_to": analysis["search_time_to"],
    "filters": {
        "server_ip": ",".join(analysis["destination_ips"]),
        "source_ip": ",".join(analysis["source_ips"]),
    },
    "limit": 200,
    "columns": ["time", "action", "respcode", "reason", "cip", "sip", "url"],
}

search = require_ok(session.post(f"{BASE_URL}/api/search", json=payload)).json()
print("rows:", search["row_count"], "truncated:", search["truncated"])
for row in search["rows"][:10]:
    print(row)
```

## Recommended Client Behavior

- Use `requests.Session()` so the login cookie is reused automatically.
- Prefer API tokens over session-cookie login for backend integrations.
- In production, validate TLS with your internal CA or public CA bundle.
- Do not rely on sessions surviving service restarts.
- Use `/api/schema` to discover the active field mapping before building integrations.
- Use RFC3339 UTC timestamps in automation.
- Use comma-separated `server_ip` values when correlating multiple destination IPs from PCAP analysis.
- Expect helpdesk masking when authenticating with a helpdesk role.
- Expect admin visibility filters to hide rows from search and dashboards.
- Keep token allowlists tight and disable unused tokens instead of leaving them dormant.

## Related Documents

- Main project guide: [README.md](/Users/roman/codex/nss-quarry/README.md)
- HTTPS install: [docs/install-https.md](/Users/roman/codex/nss-quarry/docs/install-https.md)
- OIDC setup: [docs/oidc-setup.md](/Users/roman/codex/nss-quarry/docs/oidc-setup.md)
- Security posture: [SECURITY.md](/Users/roman/codex/nss-quarry/SECURITY.md)
