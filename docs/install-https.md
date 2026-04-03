# HTTPS Installation Guide (Nginx + systemd)

This guide installs `nss-quarry` with HTTPS enabled by default.

`install.sh` does the following:
- creates unprivileged service user `nssquarry`
- installs binary to `/usr/local/bin/nss-quarry`
- installs config at `/etc/nss-quarry/config.toml`
- enforces secure defaults:
  - `bind_addr = "127.0.0.1:9191"`
  - `secure_cookie = true`
  - `redirect_url = "https://<FQDN>/auth/callback"`
- detects `nss-ingestor` / `nss-ingest` service when present
- detects/parses upstream Parquet path (from `/etc/nss-ingestor/config.toml` or `/etc/nss-ingest/config.toml`)
- prompts for `data.parquet_root` and writes it to `nss-quarry` config
- offers to grant `nssquarry` read access to Parquet data (ACL preferred, group fallback)
- installs systemd unit `/etc/systemd/system/nss-quarry.service`
- installs Nginx reverse proxy `/etc/nginx/conf.d/nss-quarry.conf`

## Prerequisites

Install dependencies:
- `nginx`
- `openssl`
- Rust toolchain (only needed if `target/release/nss-quarry` does not already exist)

Run install as root:

```bash
sudo ./install.sh
```

If dependencies are missing on Rocky/RHEL:

```bash
sudo ./install.sh --install-deps --install-rust
```

Demo/lab mode:

```bash
sudo ./install.sh --install-deps --install-rust --demo-users
```

Demo mode behavior:
- forces `auth.mode = "local_users"`
- creates these users in config (password equals username):
  - `admin` (role `admin`)
  - `analyst` (role `analyst`)
  - `helpdesk` (role `helpdesk`)

`--simple-demo-users` is an alias of `--demo-users`.

Use demo mode only for testing/training environments.

## TLS Modes

Installer prompt:
- `self_signed` (default): generates cert and key for your FQDN
- `provided`: uses existing certificate and key paths

Use `provided` in enterprise production whenever possible (internal PKI or public CA).

## Post-Install Checks

```bash
sudo systemctl status nss-quarry --no-pager
sudo systemctl status nginx --no-pager
curl -k https://<FQDN>/healthz
```

For self-signed mode, browsers show trust warnings until your CA trust is configured or cert is replaced.

## Upstream Parquet Access

`nss-quarry` must be able to read Parquet files written by `nss-to-parquet`.

Installer flow:
1. Detects ingestion service (`nss-ingestor.service` or `nss-ingest.service`) if installed.
2. Suggests detected Parquet path from upstream config.
3. Prompts you to confirm/override that path.
4. Offers automatic access grant for user `nssquarry`:
- ACL mode (`setfacl`) when available
- fallback to source directory group membership when ACL tools are unavailable

If you skip automatic grant, ensure manually that `nssquarry` has at least read/execute access on the Parquet root and subdirectories.

## Replacing Self-Signed with Enterprise Certs

Re-run installer and choose `provided`:

```bash
sudo ./install.sh
```

Then provide:
- certificate path (PEM)
- private key path (PEM)

Installer rewrites Nginx config, validates it, and reloads services.

## Service Security Model

- Installation runs as root.
- Runtime service runs as unprivileged user `nssquarry`.
- App is local-only (`127.0.0.1:9191`), externally exposed only through HTTPS proxy.

## OIDC Follow-Up

After HTTPS install, configure OIDC:
- [oidc-setup.md](/Users/roman/codex/nss-quarry/docs/oidc-setup.md)
