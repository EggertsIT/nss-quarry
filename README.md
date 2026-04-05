# nss-quarry

`nss-quarry` provides secure IT-helpdesk access to NSS Parquet logs produced by `nss-to-parquet`.

## License and Commercial Use

This project is source-available under `BUSL-1.1` (Business Source License), not OSI open source.

- License terms: `LICENSE`
- Commercial subscription terms: `COMMERCIAL_LICENSE.md`

Production/commercial use requires a paid monthly commercial subscription from the Licensor.

## Features

- Query last 14-day parquet partitions with strict guardrails (max 7-day query window by default).
- Troubleshooting dashboards and filtered search APIs.
- Aggregate-backed analytics APIs for fast summary, timeseries, and top-value reporting.
- Global country flow map (24h) using `srcip_country -> dstip_country`.
- Embedded `NSS Ingestor` dashboard tab (admin-only, via `/ingestor/*` reverse-proxy).
- Admin-only `Force Finalize Open Parquet Files` control (audited, source-IP logged).
- CSV export with audit trail.
- RBAC: `helpdesk`, `analyst`, `admin`.
- Authentication modes:
  - `oidc_entra`
  - `oidc_okta`
  - `local_users` (small environments)
- Optional API-token auth for backend automation and integrations.
- Admin-managed API tokens with source allowlists and runtime revocation.
- ServiceNow MID-friendly asynchronous investigation APIs with durable job state.
- Full audit log of auth/query/export/admin actions.
- Health probes: `/healthz`, `/readyz`.

## Build

```bash
cargo build --release
```

## HTTPS Install (Default)

`install.sh` sets up `nss-quarry` behind Nginx with HTTPS by default.

- prompts for endpoint identity (DNS name or IPv4)
- TLS modes:
  - `self_signed` (default, generated during install)
  - `provided` (use org/internal PKI cert/key)
- detects `nss-ingestor` and suggests upstream Parquet root
- prompts and writes `data.parquet_root`
- offers automatic permission grant so `nssquarry` can read upstream Parquet files
- forces `bind_addr = 127.0.0.1:9191`
- forces `auth.secure_cookie = true`
- installs a hardened systemd service running as unprivileged `nssquarry`
- when SELinux is enforcing, sets `httpd_can_network_connect=1` for nginx upstream connectivity
- configures nginx route `/ingestor/* -> 127.0.0.1:9090` for integrated ingestor dashboard

When using `self_signed`:
- DNS input generates certificate SAN `DNS:<name>`
- IPv4 input generates certificate SAN `IP:<address>`

Run:

```bash
sudo ./install.sh
```

One-line install:

```bash
git clone https://github.com/EggertsIT/nss-quarry.git && cd nss-quarry && sudo ./install.sh --install-deps --install-rust
```

Demo/lab shortcut:

```bash
sudo ./install.sh --demo-users
```

One-line demo install:

```bash
git clone https://github.com/EggertsIT/nss-quarry.git && cd nss-quarry && sudo ./install.sh --install-deps --install-rust --demo-users
```

This creates local test users:
- `admin` / `admin` (role `admin`)
- `analyst` / `analyst` (role `analyst`)
- `helpdesk` / `helpdesk` (role `helpdesk`)

Do not use `--demo-users` in production.

See full details:
- `docs/install-https.md`
- `docs/servicenow-integration.md`

## Uninstall

Standard uninstall (keeps host Rust toolchains):

```bash
sudo ./install.sh --uninstall
```

Optional: also purge `/root/.cargo` and `/root/.rustup` if they were installed by this installer:

```bash
sudo ./install.sh --uninstall --purge-rust
```

## Configuration

1. Copy template:

```bash
cp config.example.toml config.toml
```

2. Set at least:
- `data.parquet_root` to your `nss-to-parquet` output directory.
- field mapping in `data.fields` (fresh-install defaults are aligned to `nss-to-parquet` `zscaler_web_v2_ops`, including `user_field="login"` and `url_field="url"`).
  - `response_code_field` and `reason_field` drive quick filters in Search Logs (defaults: `respcode`, `reason`).
  - include `source_country_field` / `destination_country_field` for global flow map rendering (defaults: `srcip_country`, `dstip_country`).
- admin visibility filters are managed in the Dashboard `Config` tab and persisted at `/var/lib/nss-quarry/visibility_filters.json` (derived from `audit.path` directory).
- `auth.mode`
- auth settings for the chosen mode.
- query aggregate settings:
  - `query.dashboard_snapshot_refresh_secs` (hourly rebuild cadence for dashboard and analytics base snapshots)
  - `query.analytics_retention_days` (how much hourly aggregate history to keep; default `14`)
  - `query.analytics_top_n` (per-hour cap for high-cardinality dimensions such as users/devices/destination IPs; default `50`)
  - `query.analytics_cache_dir` (persisted aggregate snapshot location)
- ingestor control settings:
  - `ingestor.base_url` (default `http://127.0.0.1:9090`)
  - `ingestor.request_timeout_ms` (default `5000`)
- integration job settings:
  - `integration.job_ttl_hours` (default `24`)
  - `integration.cleanup_interval_secs` (default `600`)
  - `integration.max_csv_export_bytes` (default `5000000`)
- for production OIDC with Microsoft Entra ID or Okta, follow the dedicated guide:
  - `docs/oidc-setup.md`
- optional audit retention/rotation:
  - `audit.path` (default `/var/lib/nss-quarry/audit.log`)
  - `audit.retention_days` (`0` disables age-based cleanup)
  - `audit.rotate_max_bytes` (`0` disables size-based rotation)
  - `audit.rotate_max_files` (number of rotated files to keep when rotation is enabled)

3. Validate:

```bash
cargo run -- validate-config --config ./config.toml
```

## Local User Setup

Generate password hash:

```bash
cargo run -- hash-password --password 'StrongPasswordHere'
```

Use the output in `[[auth.local_users.users]]`.

## API Token Setup

Generate a new API token and matching Argon2 hash:

```bash
cargo run -- generate-api-token --name svc-servicenow-analyst
```

This prints:
- the plaintext token
- the Argon2 `token_hash`
- a ready-to-paste `[[auth.api_tokens.tokens]]` config snippet

Use API tokens for backend integrations such as ServiceNow. Recommended role for automation is `analyst`, not `admin`.

Runtime token handling:
- bootstrap tokens can be defined in `auth.api_tokens.tokens`
- on first run they are seeded into `/var/lib/nss-quarry/api_tokens.json` (derived from `audit.path`)
- after that, manage tokens from the Dashboard `Config` tab or the admin token APIs
- token usage and denied token attempts are audited
- each token can have a source IP/CIDR allowlist and can be disabled without restarting the service

## Run

```bash
cargo run -- run --config ./config.toml
```

## API

Full API reference with Python examples:
- `docs/api.md`
- `docs/servicenow-integration.md`

- `GET /healthz`
- `GET /readyz`
- `GET /auth/login` (OIDC modes)
- `POST /auth/login` (local mode, JSON username/password)
- `GET /auth/callback` (OIDC callback)
- `POST /auth/logout`
- `GET /api/me`
- `POST /api/search`
- `POST /api/export/csv`
- `POST /api/export/pdf-summary` (support-summary PDF for current search window)
- `GET /api/analytics/summary`
- `GET /api/analytics/timeseries`
- `GET /api/analytics/top`
- `POST /api/integrations/servicenow/investigations`
- `GET /api/integrations/servicenow/jobs/{job_id}`
- `GET /api/integrations/servicenow/jobs/{job_id}/result`
- `GET /api/integrations/servicenow/jobs/{job_id}/export.csv?token=...`
- `POST /api/pcap/analyze` (multipart upload: `pcap` file + optional `max_ips`)
- `GET /api/dashboards/{name}` (`?refresh=delta` supported for manual current-window refresh)
- `GET /api/audit` (admin only, server-side pagination and filtering)
- `GET /api/audit/export/csv` (admin only, filter-aware export; capped to 50k rows)
- `GET /api/admin/api-tokens` (admin only; lists managed API tokens)
- `POST /api/admin/api-tokens` (admin only; creates a new API token and returns the plaintext token once)
- `PUT /api/admin/api-tokens/{name}` (admin only; updates role, source allowlist, and enabled/disabled state)
- `GET /api/admin/visibility-filters` (admin only; returns URL regex + blocked IP exclusion rules)
- `PUT /api/admin/visibility-filters` (admin only; updates and persists exclusion rules)
- `POST /api/admin/ingestor/force-finalize-open-files` (admin only; calls `nss-ingestor` force-finalize API and writes audit event with actor/time/source IP)

API authentication:
- session cookie for browser and interactive login
- `Authorization: Bearer <token>` or `X-API-Token: <token>` for automation API clients
- API tokens can be source-restricted by IP or CIDR and disabled at runtime

Dashboard behavior:
- the main dashboard is served from a persisted hourly snapshot, not a live full 24-hour parquet scan on every page load
- `query.dashboard_snapshot_refresh_secs` controls the hourly rebuild cadence
- `query.analytics_retention_days` controls how much hourly aggregate history is kept for reporting APIs
- `query.analytics_top_n` caps high-cardinality aggregate dimensions per hour to keep read-side storage bounded
- `query.analytics_cache_dir` controls where persisted aggregate snapshots are stored
- the browser `Refresh` button requests `?refresh=delta`, which merges newer finalized parquet data on top of the latest hourly snapshot when available
- dashboard responses include explicit state and freshness metadata such as `status`, `source`, `snapshot_generated_at`, `snapshot_age_seconds`, `data_window_from`, `data_window_to`, `refresh_in_progress`, `last_refresh_attempt_at`, `last_refresh_success_at`, `last_refresh_error`, and `notes`

`/api/audit` query parameters:
- `page` (default `1`)
- `page_size` (default `50`, max `500`)
- `from` / `to` (RFC3339 timestamps)
- `actor`, `action`, `outcome`, `text` (case-insensitive contains filters)

`/api/pcap/analyze` notes:
- supports classic `.pcap` and `.pcapng`
- extracts capture start/end and unique destination IPs
- dashboard auto-applies padded search window + SIP list to Search Logs
- default padding is `-5 minutes` before capture start and `+5 minutes` after capture end
- upload cap is `5 GiB` per request
- uploads are streamed to a temporary file before analysis (does not load full file into memory)
- nginx upload limit is set to `6g` by installer (`client_max_body_size 6g`)

## Security Notes

- Keep service bound to localhost and publish through an authenticated reverse proxy.
- In `helpdesk` role, fields in `security.helpdesk_mask_fields` are redacted.
- HTTPS is the default install path (`install.sh`) and uses `auth.secure_cookie = true`.
- Set `secure_cookie = false` only for isolated local HTTP testing.
- Prefer `analyst` API tokens for integrations; avoid `admin` tokens unless the workflow truly needs admin APIs.
- Keep audit log path protected by filesystem permissions.
- For enterprise SSO design, role claim strategy, and troubleshooting:
  - `docs/oidc-setup.md`

## Security Policy and Pentest

- Security policy and release verification:
  - `SECURITY.md`
- Latest internal penetration test report:
  - `pentest.md`
- Threat model:
  - `docs/threat-model.md`

## Dependency Audit Policy

Run local dependency audit with project allowlist:

```bash
cargo install cargo-audit --locked
./scripts/run_audit.sh
```

Run local deny policy checks:

```bash
cargo install cargo-deny --locked
cargo deny check --config deny.toml advisories
```

Current temporary allowlist entries are documented in:
- `audit-allowlist.txt`

## Signed Release Artifacts

Tag releases (`v*`) produce:
- Linux binary (`nss-quarry-linux-x86_64`)
- SHA-256 checksums
- keyless `cosign` signature + certificate
- CycloneDX SBOM (`sbom.cdx.json`)

CI workflows:
- `.github/workflows/ci.yml`
- `.github/workflows/release-artifacts.yml`

## Troubleshooting

If queries fail with:

`IO Error: No files found that match the pattern ".../dt=*/hour=*/*.parquet"`

verify parent directory traversal permissions for `nssquarry`:

```bash
sudo setfacl -m u:nssquarry:--x /var/lib/nss-ingestor
sudo setfacl -m u:nssquarry:rX /var/lib/nss-ingestor/data
sudo setfacl -R -m u:nssquarry:rX /var/lib/nss-ingestor/data
curl -k https://127.0.0.1/readyz
```

If PCAP Assist returns HTTP `413`:

```bash
sudo sed -n '1,200p' /etc/nginx/conf.d/nss-quarry.conf | grep client_max_body_size
sudo nginx -t
sudo systemctl reload nginx
```

If permissions are correct but recent data is still missing, check `nss-to-parquet` writer finalization settings.  
Low-volume traffic can remain in an open `.parquet.tmp` writer until rotation/finalize triggers.  
Set `writer.max_file_age_secs` (for example `60`) in `nss-ingestor` config so files are finalized and queryable on a fixed interval.
