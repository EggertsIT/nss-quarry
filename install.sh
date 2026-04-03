#!/usr/bin/env bash
set -euo pipefail

DEMO_USERS=0
INSTALL_DEPS=0
INSTALL_RUST=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --demo-users, --simple-demo-users
      Create demo local users:
        - admin (role: admin, password: admin)
        - analyst (role: analyst, password: analyst)
        - helpdesk (role: helpdesk, password: helpdesk)
      Intended only for lab/testing/demo.
  --install-deps
      Auto-install OS dependencies on RHEL/Rocky via dnf (nginx, openssl, acl, build tools).
  --install-rust
      If cargo is missing and a build is required, install Rust toolchain via rustup.
  -h, --help
      Show this help text.
EOF
}

log() {
  echo "[install] $*"
}

fail() {
  echo "[install] ERROR: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo-users|--simple-demo-users)
      DEMO_USERS=1
      shift
      ;;
    --install-deps)
      INSTALL_DEPS=1
      shift
      ;;
    --install-rust)
      INSTALL_RUST=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1 (use --help)"
      ;;
  esac
done

install_os_dependencies() {
  require_cmd dnf
  log "Installing OS dependencies via dnf"
  dnf install -y \
    nginx \
    openssl \
    acl \
    curl \
    ca-certificates \
    gcc \
    gcc-c++ \
    make \
    pkgconf-pkg-config
}

install_rust_toolchain() {
  if command -v cargo >/dev/null 2>&1; then
    return 0
  fi
  require_cmd curl
  log "Installing Rust toolchain via rustup (stable, minimal profile)"
  local tmp_installer="/tmp/rustup-init.sh"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$tmp_installer"
  sh "$tmp_installer" -y --profile minimal --default-toolchain stable
  rm -f "$tmp_installer"
  if [[ -f "/root/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source /root/.cargo/env
  fi
  command -v cargo >/dev/null 2>&1 || fail "cargo still missing after rustup install"
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "missing required command: $cmd"
}

prompt() {
  local var_name="$1"
  local label="$2"
  local default_value="$3"
  local value
  read -r -p "$label [$default_value]: " value
  value="${value:-$default_value}"
  printf -v "$var_name" '%s' "$value"
}

yes_no_default_yes() {
  local var_name="$1"
  local label="$2"
  local value
  read -r -p "$label [yes]: " value
  value="${value:-yes}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  if [[ "$value" != "yes" && "$value" != "no" ]]; then
    fail "please answer yes or no"
  fi
  printf -v "$var_name" '%s' "$value"
}

set_kv_line() {
  local file="$1"
  local key_regex="$2"
  local replacement="$3"
  if grep -Eq "$key_regex" "$file"; then
    sed -E -i "s|$key_regex.*|$replacement|" "$file"
  else
    echo "$replacement" >>"$file"
  fi
}

have_service_unit() {
  local unit="$1"
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$unit"
}

resolve_parquet_root_from_ingestor_config() {
  local cfg="$1"
  [[ -f "$cfg" ]] || return 1
  local out
  out="$(sed -nE 's/^[[:space:]]*output_dir[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' "$cfg" | head -n1)"
  [[ -n "$out" ]] || return 1
  if [[ "$out" = /* ]]; then
    printf '%s' "$out"
  else
    printf '%s/%s' "$(dirname "$cfg")" "$out"
  fi
}

grant_parquet_access() {
  local parquet_root="$1"
  local app_user="$2"

  if [[ ! -d "$parquet_root" ]]; then
    log "Parquet root does not exist yet: $parquet_root"
    log "Continuing install; create/mount it before running production queries."
    return 0
  fi

  if command -v setfacl >/dev/null 2>&1; then
    log "Granting read access using ACLs"
    setfacl -m "u:${app_user}:rX" "$parquet_root"
    setfacl -R -m "u:${app_user}:rX" "$parquet_root"
    find "$parquet_root" -type d -exec setfacl -m "d:u:${app_user}:rX" {} +
    return 0
  fi

  local src_group
  src_group="$(stat -c '%G' "$parquet_root" 2>/dev/null || true)"
  if [[ -n "$src_group" && "$src_group" != "UNKNOWN" ]]; then
    log "setfacl not found; adding $app_user to source group $src_group"
    usermod -a -G "$src_group" "$app_user"
    return 0
  fi

  fail "unable to grant parquet access automatically (missing setfacl and no valid source group)"
}

hash_password_cli() {
  local bin_path="$1"
  local plain="$2"
  "$bin_path" hash-password --password "$plain" | tail -n1
}

append_demo_user_if_missing() {
  local cfg="$1"
  local username="$2"
  local hash="$3"
  local role="$4"

  if grep -Eq "^[[:space:]]*username[[:space:]]*=[[:space:]]*\"${username}\"[[:space:]]*$" "$cfg"; then
    log "Demo user '$username' already present in config; skipping"
    return 0
  fi

  cat >>"$cfg" <<EOF

[[auth.local_users.users]]
username = "$username"
password_hash = "$hash"
role = "$role"
disabled = false
EOF
  log "Added demo user '$username' with role '$role'"
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  fail "run install.sh as root (it installs system files). The service itself runs as an unprivileged user."
fi

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  install_os_dependencies
fi

require_cmd id
require_cmd useradd
require_cmd install
require_cmd sed
require_cmd systemctl
require_cmd openssl
require_cmd nginx

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="${APP_USER:-nssquarry}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
ETC_DIR="${ETC_DIR:-/etc/nss-quarry}"
DATA_DIR="${DATA_DIR:-/var/lib/nss-quarry}"
CONFIG_PATH="${CONFIG_PATH:-$ETC_DIR/config.toml}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/nss-quarry}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/nss-quarry.service}"
CERT_DIR="${CERT_DIR:-$ETC_DIR/certs}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/conf.d/nss-quarry.conf}"

log "HTTPS-first installer for nss-quarry"
prompt FQDN "Public DNS name for nss-quarry" "nss-quarry.example.com"
prompt TLS_MODE "TLS mode (self_signed/provided)" "self_signed"

if [[ "$TLS_MODE" != "self_signed" && "$TLS_MODE" != "provided" ]]; then
  fail "TLS mode must be 'self_signed' or 'provided'"
fi

TLS_CERT=""
TLS_KEY=""
if [[ "$TLS_MODE" == "provided" ]]; then
  prompt TLS_CERT "Path to TLS certificate (PEM)" "/etc/pki/tls/certs/nss-quarry.crt"
  prompt TLS_KEY "Path to TLS private key (PEM)" "/etc/pki/tls/private/nss-quarry.key"
  [[ -f "$TLS_CERT" ]] || fail "certificate not found: $TLS_CERT"
  [[ -f "$TLS_KEY" ]] || fail "key not found: $TLS_KEY"
fi

INGESTOR_UNIT=""
INGESTOR_CONFIG=""
DETECTED_PARQUET_ROOT="/var/lib/nss-ingestor/data"
if have_service_unit "nss-ingestor.service"; then
  INGESTOR_UNIT="nss-ingestor.service"
  INGESTOR_CONFIG="/etc/nss-ingestor/config.toml"
elif have_service_unit "nss-ingest.service"; then
  INGESTOR_UNIT="nss-ingest.service"
  INGESTOR_CONFIG="/etc/nss-ingest/config.toml"
fi

if [[ -n "$INGESTOR_UNIT" ]]; then
  log "Detected upstream ingestion service: $INGESTOR_UNIT"
  if detected="$(resolve_parquet_root_from_ingestor_config "$INGESTOR_CONFIG")"; then
    DETECTED_PARQUET_ROOT="$detected"
    log "Detected parquet root from $INGESTOR_CONFIG: $DETECTED_PARQUET_ROOT"
  else
    log "Could not parse parquet root from $INGESTOR_CONFIG, using default $DETECTED_PARQUET_ROOT"
  fi
else
  log "No nss-ingestor/nss-ingest service detected. Provide parquet root manually."
fi

prompt PARQUET_ROOT "Path to nss-to-parquet output directory" "$DETECTED_PARQUET_ROOT"
yes_no_default_yes GRANT_PARQUET_ACCESS "Grant $APP_USER read access to $PARQUET_ROOT now?"

log "Ensuring service user exists: $APP_USER"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$DATA_DIR" --shell /sbin/nologin "$APP_USER"
fi

log "Creating directories"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$DATA_DIR"
install -d -m 0750 -o root -g "$APP_GROUP" "$ETC_DIR"
install -d -m 0750 -o root -g "$APP_GROUP" "$CERT_DIR"

if [[ ! -x "$SCRIPT_DIR/target/release/nss-quarry" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    if [[ "$INSTALL_RUST" -eq 1 ]]; then
      install_rust_toolchain
    else
      fail "cargo is missing and no prebuilt binary found. Re-run with --install-rust or build manually before install."
    fi
  fi
  log "Building release binary"
  (cd "$SCRIPT_DIR" && cargo build --release)
fi

log "Installing binary to $BIN_PATH"
install -m 0755 "$SCRIPT_DIR/target/release/nss-quarry" "$BIN_PATH"

if [[ ! -f "$CONFIG_PATH" ]]; then
  log "Installing initial config to $CONFIG_PATH"
  install -m 0640 -o root -g "$APP_GROUP" "$SCRIPT_DIR/config.example.toml" "$CONFIG_PATH"
else
  log "Config exists, preserving: $CONFIG_PATH"
fi

log "Applying secure baseline to config"
set_kv_line "$CONFIG_PATH" '^bind_addr = ' 'bind_addr = "127.0.0.1:9191"'
set_kv_line "$CONFIG_PATH" '^parquet_root = ' "parquet_root = \"$PARQUET_ROOT\""
set_kv_line "$CONFIG_PATH" '^secure_cookie = ' 'secure_cookie = true'
set_kv_line "$CONFIG_PATH" '^redirect_url = ' "redirect_url = \"https://$FQDN/auth/callback\""
chown root:"$APP_GROUP" "$CONFIG_PATH"
chmod 0640 "$CONFIG_PATH"

if [[ "$GRANT_PARQUET_ACCESS" == "yes" ]]; then
  grant_parquet_access "$PARQUET_ROOT" "$APP_USER"
else
  log "Skipped automatic parquet permission grant. Ensure $APP_USER can read $PARQUET_ROOT."
fi

if [[ "$DEMO_USERS" -eq 1 ]]; then
  log "Demo user mode enabled (testing/lab only)"
  set_kv_line "$CONFIG_PATH" '^mode = ' 'mode = "local_users"'

  admin_hash="$(hash_password_cli "$BIN_PATH" "admin")"
  analyst_hash="$(hash_password_cli "$BIN_PATH" "analyst")"
  helpdesk_hash="$(hash_password_cli "$BIN_PATH" "helpdesk")"

  append_demo_user_if_missing "$CONFIG_PATH" "admin" "$admin_hash" "admin"
  append_demo_user_if_missing "$CONFIG_PATH" "analyst" "$analyst_hash" "analyst"
  append_demo_user_if_missing "$CONFIG_PATH" "helpdesk" "$helpdesk_hash" "helpdesk"

  log "Demo credentials:"
  log "  admin / admin (role=admin)"
  log "  analyst / analyst (role=analyst)"
  log "  helpdesk / helpdesk (role=helpdesk)"
  log "Do NOT use --demo-users in production."
fi

if [[ "$TLS_MODE" == "self_signed" ]]; then
  TLS_CERT="$CERT_DIR/$FQDN.crt"
  TLS_KEY="$CERT_DIR/$FQDN.key"
  if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
    log "Generating self-signed TLS certificate for $FQDN"
    openssl req \
      -x509 \
      -newkey rsa:4096 \
      -sha256 \
      -nodes \
      -days 825 \
      -subj "/CN=$FQDN" \
      -addext "subjectAltName=DNS:$FQDN" \
      -keyout "$TLS_KEY" \
      -out "$TLS_CERT"
  else
    log "Using existing self-signed cert at $TLS_CERT"
  fi
  chown root:"$APP_GROUP" "$TLS_CERT" "$TLS_KEY"
  chmod 0640 "$TLS_CERT" "$TLS_KEY"
fi

log "Validating config as service user"
if command -v runuser >/dev/null 2>&1; then
  runuser -u "$APP_USER" -- "$BIN_PATH" validate-config --config "$CONFIG_PATH"
else
  su -s /bin/bash -c "\"$BIN_PATH\" validate-config --config \"$CONFIG_PATH\"" "$APP_USER"
fi

log "Writing systemd unit: $SERVICE_PATH"
cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=NSS Quarry (Parquet query and dashboard service)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
ExecStart=$BIN_PATH run --config $CONFIG_PATH
Restart=always
RestartSec=3
WorkingDirectory=$DATA_DIR
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

log "Writing nginx TLS reverse proxy: $NGINX_CONF"
cat >"$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $FQDN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $FQDN;

    ssl_certificate $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:9191;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;
    }
}
EOF

log "Validating nginx config"
nginx -t

log "Reloading systemd and enabling services"
systemctl daemon-reload
systemctl enable --now nss-quarry
systemctl enable --now nginx
systemctl reload nginx

log "Install complete."
log "Service status: systemctl status nss-quarry --no-pager"
log "Health check: curl -k https://$FQDN/healthz"
log "Configured parquet root: $PARQUET_ROOT"
if [[ "$TLS_MODE" == "self_signed" ]]; then
  log "Note: self-signed cert installed. Replace with org-trusted certs by rerunning with TLS mode 'provided'."
fi
