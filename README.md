# nss-quarry

`nss-quarry` provides secure IT-helpdesk access to NSS Parquet logs produced by `nss-to-parquet`.

## Features

- Query last 14-day parquet partitions with strict guardrails (max 7-day query window by default).
- Troubleshooting dashboards and filtered search APIs.
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
- `GET /api/audit` (admin only)

## Security Notes

- Keep service bound to localhost and publish through an authenticated reverse proxy.
- In `helpdesk` role, fields in `security.helpdesk_mask_fields` are redacted.
- HTTPS is the default install path (`install.sh`) and uses `auth.secure_cookie = true`.
- Set `secure_cookie = false` only for isolated local HTTP testing.
- Keep audit log path protected by filesystem permissions.
- For enterprise SSO design, role claim strategy, and troubleshooting:
  - `docs/oidc-setup.md`
