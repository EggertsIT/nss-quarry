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
- Embedded `NSS Ingestor` dashboard tab (admin-only, via `/ingestor/*` reverse-proxy).
- CSV export with audit trail.
- RBAC: `helpdesk`, `analyst`, `admin`.
- Authentication modes:
  - `oidc_entra`
  - `oidc_okta`
  - `local_users` (small environments)
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
- `auth.mode`
- auth settings for the chosen mode.
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

## Run

```bash
cargo run -- run --config ./config.toml
```

## API

- `GET /healthz`
- `GET /readyz`
- `GET /auth/login` (OIDC modes)
- `POST /auth/login` (local mode, JSON username/password)
- `GET /auth/callback` (OIDC callback)
- `POST /auth/logout`
- `GET /api/me`
- `POST /api/search`
- `POST /api/export/csv`
- `GET /api/dashboards/{name}`
- `GET /api/audit` (admin only, server-side pagination and filtering)
- `GET /api/audit/export/csv` (admin only, filter-aware export; capped to 50k rows)

`/api/audit` query parameters:
- `page` (default `1`)
- `page_size` (default `50`, max `500`)
- `from` / `to` (RFC3339 timestamps)
- `actor`, `action`, `outcome`, `text` (case-insensitive contains filters)

## Security Notes

- Keep service bound to localhost and publish through an authenticated reverse proxy.
- In `helpdesk` role, fields in `security.helpdesk_mask_fields` are redacted.
- HTTPS is the default install path (`install.sh`) and uses `auth.secure_cookie = true`.
- Set `secure_cookie = false` only for isolated local HTTP testing.
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
