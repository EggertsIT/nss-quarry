#!/usr/bin/env bash
set -euo pipefail

DEMO_USERS=0
INSTALL_DEPS=0
INSTALL_RUST=0
UNINSTALL=0
YES=0
PURGE_RUST=0
RUST_INSTALLED_BY_INSTALLER=0

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
      Auto-install OS dependencies on RHEL/Rocky via dnf (nginx, openssl, acl, SELinux tools, build tools).
  --install-rust
      If cargo is missing and a build is required, install Rust toolchain via rustup.
  --uninstall
      Remove nss-quarry and revert installer-managed changes.
  --purge-rust
      Only with --uninstall: also remove Rust toolchain if it was installed by this installer.
  --yes
      Non-interactive yes for uninstall confirmation prompts.
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
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --yes)
      YES=1
      shift
      ;;
    --purge-rust)
      PURGE_RUST=1
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

if [[ "$UNINSTALL" -eq 1 && ("$INSTALL_DEPS" -eq 1 || "$INSTALL_RUST" -eq 1 || "$DEMO_USERS" -eq 1) ]]; then
  fail "--uninstall cannot be combined with install/demo flags"
fi
if [[ "$UNINSTALL" -eq 0 && "$PURGE_RUST" -eq 1 ]]; then
  fail "--purge-rust can only be used together with --uninstall"
fi

APP_USER="${APP_USER:-nssquarry}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
ETC_DIR="${ETC_DIR:-/etc/nss-quarry}"
DATA_DIR="${DATA_DIR:-/var/lib/nss-quarry}"
CONFIG_PATH="${CONFIG_PATH:-$ETC_DIR/config.toml}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/nss-quarry}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/nss-quarry.service}"
CERT_DIR="${CERT_DIR:-$ETC_DIR/certs}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/conf.d/nss-quarry.conf}"
STATE_FILE="${STATE_FILE:-$ETC_DIR/install-state.env}"

install_os_dependencies() {
  require_cmd dnf
  log "Installing OS dependencies via dnf"
  dnf install -y \
    nginx \
    openssl \
    acl \
    policycoreutils-python-utils \
    curl \
    ca-certificates \
    gcc \
    gcc-c++ \
    make \
    pkgconf-pkg-config
}

ensure_selinux_nginx_connect() {
  if ! command -v getenforce >/dev/null 2>&1; then
    return 0
  fi

  local selinux_mode
  selinux_mode="$(getenforce 2>/dev/null || true)"
  case "$selinux_mode" in
    Disabled|"")
      return 0
      ;;
    Enforcing|Permissive)
      ;;
    *)
      warn "Unknown SELinux mode '$selinux_mode'; skipping SELinux nginx boolean check."
      return 0
      ;;
  esac

  if ! command -v getsebool >/dev/null 2>&1 || ! command -v setsebool >/dev/null 2>&1; then
    if [[ "$selinux_mode" == "Enforcing" ]]; then
      fail "SELinux is Enforcing but getsebool/setsebool is missing. Install policycoreutils-python-utils and rerun."
    fi
    warn "SELinux is $selinux_mode but getsebool/setsebool not found; skipping automatic boolean setup."
    return 0
  fi

  local current
  current="$(getsebool httpd_can_network_connect 2>/dev/null | awk '{print $3}' || true)"
  if [[ "$current" == "on" ]]; then
    log "SELinux boolean already set: httpd_can_network_connect=on"
    return 0
  fi

  log "Enabling SELinux boolean: httpd_can_network_connect=1 (required for nginx -> nss-quarry upstream)"
  if ! setsebool -P httpd_can_network_connect 1; then
    if [[ "$selinux_mode" == "Enforcing" ]]; then
      fail "Failed to set SELinux boolean httpd_can_network_connect while SELinux is Enforcing."
    fi
    warn "Failed to set SELinux boolean httpd_can_network_connect."
    return 0
  fi
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
  RUST_INSTALLED_BY_INSTALLER=1
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
  local load_state
  load_state="$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)"
  if [[ "$load_state" == "loaded" || "$load_state" == "masked" ]]; then
    return 0
  fi

  if systemctl cat "$unit" >/dev/null 2>&1; then
    return 0
  fi

  if [[ -f "/etc/systemd/system/$unit" || -f "/usr/lib/systemd/system/$unit" || -f "/lib/systemd/system/$unit" ]]; then
    return 0
  fi

  return 1
}

is_ipv4_address() {
  local ip="$1"
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 1
  fi
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    if ((octet < 0 || octet > 255)); then
      return 1
    fi
  done
  return 0
}

url_host_component() {
  local host="$1"
  # Currently only special-case IPv4; DNS names pass through.
  printf '%s' "$host"
}

sanitize_cert_name() {
  local raw="$1"
  printf '%s' "$raw" | sed -E 's/[^A-Za-z0-9._-]+/_/g'
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
    local parent
    parent="$(dirname "$parquet_root")"
    while [[ -n "$parent" && "$parent" != "/" ]]; do
      setfacl -m "u:${app_user}:--x" "$parent"
      parent="$(dirname "$parent")"
    done

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

remove_local_user_blocks_by_username() {
  local cfg="$1"
  local username="$2"
  local tmp
  tmp="$(mktemp "${cfg}.tmp.XXXXXX")"

  awk -v target_user="$username" '
BEGIN {
  in_block = 0
  skip_block = 0
  n = 0
}

function flush_block() {
  if (!in_block) return
  if (!skip_block) {
    for (i = 1; i <= n; i++) {
      print block[i]
    }
  }
  in_block = 0
  skip_block = 0
  n = 0
}

/^\[\[auth\.local_users\.users\]\][[:space:]]*$/ {
  flush_block()
  in_block = 1
  block[++n] = $0
  next
}

{
  if (in_block) {
    block[++n] = $0
    if ($0 ~ /^[[:space:]]*username[[:space:]]*=/) {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/".*$/, "", line)
      if (line == target_user) {
        skip_block = 1
      }
    }
    next
  }
  print
}

END {
  flush_block()
}
' "$cfg" >"$tmp"

  chmod --reference="$cfg" "$tmp"
  chown --reference="$cfg" "$tmp"
  mv "$tmp" "$cfg"
}

upsert_local_user() {
  local cfg="$1"
  local username="$2"
  local hash="$3"
  local role="$4"

  remove_local_user_blocks_by_username "$cfg" "$username"

  cat >>"$cfg" <<EOF

[[auth.local_users.users]]
username = "$username"
password_hash = "$hash"
role = "$role"
disabled = false
EOF
  log "Configured local user '$username' with role '$role'"
}

confirm_default_no() {
  local question="$1"
  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi
  local answer
  read -r -p "$question [no]: " answer
  answer="${answer:-no}"
  answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
  [[ "$answer" == "yes" || "$answer" == "y" ]]
}

backup_file_if_exists() {
  local src="$1"
  local backup="$2"
  if [[ -f "$src" ]]; then
    install -d -m 0750 -o root -g "$APP_GROUP" "$(dirname "$backup")"
    cp -a "$src" "$backup"
    return 0
  fi
  return 1
}

restore_or_remove() {
  local target="$1"
  local backup="$2"
  if [[ -n "$backup" && -f "$backup" ]]; then
    install -d -m 0755 -o root -g root "$(dirname "$target")"
    cp -a "$backup" "$target"
  else
    rm -f "$target"
  fi
}

write_install_state() {
  local file="$1"
  install -d -m 0750 -o root -g "$APP_GROUP" "$(dirname "$file")"
  cat >"$file" <<EOF
APP_USER=$APP_USER
APP_GROUP=$APP_GROUP
ETC_DIR=$ETC_DIR
DATA_DIR=$DATA_DIR
CONFIG_PATH=$CONFIG_PATH
BIN_PATH=$BIN_PATH
SERVICE_PATH=$SERVICE_PATH
CERT_DIR=$CERT_DIR
NGINX_CONF=$NGINX_CONF
PARQUET_ROOT=$PARQUET_ROOT
TLS_MODE=$TLS_MODE
TLS_CERT=$TLS_CERT
TLS_KEY=$TLS_KEY
APP_USER_CREATED=$APP_USER_CREATED
APP_GROUP_CREATED=$APP_GROUP_CREATED
ETC_DIR_CREATED=$ETC_DIR_CREATED
DATA_DIR_CREATED=$DATA_DIR_CREATED
CONFIG_BACKUP=$CONFIG_BACKUP
SERVICE_BACKUP=$SERVICE_BACKUP
NGINX_BACKUP=$NGINX_BACKUP
BIN_BACKUP=$BIN_BACKUP
SELF_SIGNED_CERT_CREATED=$SELF_SIGNED_CERT_CREATED
RUST_INSTALLED_BY_INSTALLER=$RUST_INSTALLED_BY_INSTALLER
EOF
  chmod 0600 "$file"
}

uninstall_routine() {
  if [[ ! -f "$STATE_FILE" ]]; then
    log "No install state file found at $STATE_FILE. Proceeding with defaults."
  else
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi

  APP_USER="${APP_USER:-nssquarry}"
  APP_GROUP="${APP_GROUP:-$APP_USER}"
  ETC_DIR="${ETC_DIR:-/etc/nss-quarry}"
  DATA_DIR="${DATA_DIR:-/var/lib/nss-quarry}"
  CONFIG_PATH="${CONFIG_PATH:-$ETC_DIR/config.toml}"
  BIN_PATH="${BIN_PATH:-/usr/local/bin/nss-quarry}"
  SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/nss-quarry.service}"
  CERT_DIR="${CERT_DIR:-$ETC_DIR/certs}"
  NGINX_CONF="${NGINX_CONF:-/etc/nginx/conf.d/nss-quarry.conf}"

  CONFIG_BACKUP="${CONFIG_BACKUP:-}"
  SERVICE_BACKUP="${SERVICE_BACKUP:-}"
  NGINX_BACKUP="${NGINX_BACKUP:-}"
  BIN_BACKUP="${BIN_BACKUP:-}"
  APP_USER_CREATED="${APP_USER_CREATED:-0}"
  APP_GROUP_CREATED="${APP_GROUP_CREATED:-0}"
  ETC_DIR_CREATED="${ETC_DIR_CREATED:-0}"
  DATA_DIR_CREATED="${DATA_DIR_CREATED:-0}"
  SELF_SIGNED_CERT_CREATED="${SELF_SIGNED_CERT_CREATED:-0}"
  RUST_INSTALLED_BY_INSTALLER="${RUST_INSTALLED_BY_INSTALLER:-0}"
  TLS_CERT="${TLS_CERT:-}"
  TLS_KEY="${TLS_KEY:-}"

  if ! confirm_default_no "Uninstall nss-quarry and revert installer-managed changes?"; then
    log "Uninstall cancelled."
    exit 0
  fi

  log "Stopping and disabling nss-quarry service"
  systemctl disable --now nss-quarry >/dev/null 2>&1 || true

  log "Restoring/removing systemd unit"
  restore_or_remove "$SERVICE_PATH" "$SERVICE_BACKUP"
  systemctl daemon-reload

  log "Restoring/removing nginx config"
  restore_or_remove "$NGINX_CONF" "$NGINX_BACKUP"
  if systemctl is-active --quiet nginx; then
    systemctl reload nginx || true
  fi

  log "Restoring/removing config and binary"
  restore_or_remove "$CONFIG_PATH" "$CONFIG_BACKUP"
  restore_or_remove "$BIN_PATH" "$BIN_BACKUP"

  if [[ "$SELF_SIGNED_CERT_CREATED" == "1" ]]; then
    log "Removing installer-generated self-signed certs"
    rm -f "$TLS_CERT" "$TLS_KEY"
  fi

  if [[ "$PURGE_RUST" == "1" ]] && [[ "$RUST_INSTALLED_BY_INSTALLER" == "1" ]]; then
    if confirm_default_no "Remove /root/.cargo and /root/.rustup toolchains installed by this script?"; then
      log "Removing installer-managed Rust toolchain from /root"
      rm -rf /root/.cargo /root/.rustup
    else
      log "Skipping Rust toolchain purge."
    fi
  elif [[ "$PURGE_RUST" == "1" ]]; then
    log "Rust purge requested but state does not indicate installer-managed Rust. Skipping."
  fi

  if [[ "$DATA_DIR_CREATED" == "1" ]]; then
    log "Removing installer-created data dir $DATA_DIR"
    rm -rf "$DATA_DIR"
  fi

  if [[ "$ETC_DIR_CREATED" == "1" ]]; then
    log "Removing installer-created config dir $ETC_DIR"
    rm -rf "$ETC_DIR"
  else
    rm -f "$STATE_FILE"
  fi

  if [[ "$APP_USER_CREATED" == "1" ]] && id -u "$APP_USER" >/dev/null 2>&1; then
    log "Removing installer-created user $APP_USER"
    userdel "$APP_USER" >/dev/null 2>&1 || true
  fi
  if [[ "$APP_GROUP_CREATED" == "1" ]] && getent group "$APP_GROUP" >/dev/null 2>&1; then
    log "Removing installer-created group $APP_GROUP"
    groupdel "$APP_GROUP" >/dev/null 2>&1 || true
  fi

  log "Uninstall complete."
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  fail "run install.sh as root (it installs system files). The service itself runs as an unprivileged user."
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
  require_cmd systemctl
  require_cmd id
  require_cmd getent
  uninstall_routine
  exit 0
fi

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  install_os_dependencies
fi

require_cmd id
require_cmd getent
require_cmd useradd
require_cmd usermod
require_cmd groupadd
require_cmd install
require_cmd sed
require_cmd systemctl
require_cmd openssl
require_cmd nginx

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "HTTPS-first installer for nss-quarry"
prompt FQDN "Public DNS name or IPv4 for nss-quarry" "nss-quarry.example.com"
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
if have_service_unit "nss-ingestor.service" || [[ -f "/etc/nss-ingestor/config.toml" ]]; then
  INGESTOR_UNIT="nss-ingestor.service"
  INGESTOR_CONFIG="/etc/nss-ingestor/config.toml"
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
  log "No nss-ingestor.service detected. Provide parquet root manually."
fi

prompt PARQUET_ROOT "Path to nss-to-parquet output directory" "$DETECTED_PARQUET_ROOT"
yes_no_default_yes GRANT_PARQUET_ACCESS "Grant $APP_USER read access to $PARQUET_ROOT now?"

APP_USER_CREATED=0
APP_GROUP_CREATED=0
ETC_DIR_CREATED=0
DATA_DIR_CREATED=0
SELF_SIGNED_CERT_CREATED=0
CONFIG_BACKUP=""
SERVICE_BACKUP=""
NGINX_BACKUP=""
BIN_BACKUP=""

if [[ ! -d "$ETC_DIR" ]]; then
  ETC_DIR_CREATED=1
fi
if [[ ! -d "$DATA_DIR" ]]; then
  DATA_DIR_CREATED=1
fi

group_existed=1
if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
  group_existed=0
  log "Creating service group $APP_GROUP"
  groupadd --system "$APP_GROUP"
  APP_GROUP_CREATED=1
fi

log "Ensuring service user exists: $APP_USER"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$DATA_DIR" --shell /sbin/nologin --gid "$APP_GROUP" "$APP_USER"
  APP_USER_CREATED=1
elif [[ "$group_existed" -eq 0 ]]; then
  # User existed but group did not; make sure runtime user can access group-owned paths.
  usermod -a -G "$APP_GROUP" "$APP_USER"
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

BACKUP_DIR="$ETC_DIR/backups"
bin_backup_candidate="$BACKUP_DIR/nss-quarry.bin.preinstall"
if backup_file_if_exists "$BIN_PATH" "$bin_backup_candidate"; then
  BIN_BACKUP="$bin_backup_candidate"
fi

log "Installing binary to $BIN_PATH"
install -m 0755 "$SCRIPT_DIR/target/release/nss-quarry" "$BIN_PATH"

config_backup_candidate="$BACKUP_DIR/config.toml.preinstall"
if backup_file_if_exists "$CONFIG_PATH" "$config_backup_candidate"; then
  CONFIG_BACKUP="$config_backup_candidate"
fi

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
set_kv_line "$CONFIG_PATH" '^redirect_url = ' "redirect_url = \"https://$(url_host_component "$FQDN")/auth/callback\""
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

  upsert_local_user "$CONFIG_PATH" "admin" "$admin_hash" "admin"
  upsert_local_user "$CONFIG_PATH" "analyst" "$analyst_hash" "analyst"
  upsert_local_user "$CONFIG_PATH" "helpdesk" "$helpdesk_hash" "helpdesk"

  log "Demo credentials:"
  log "  admin / admin (role=admin)"
  log "  analyst / analyst (role=analyst)"
  log "  helpdesk / helpdesk (role=helpdesk)"
  log "Do NOT use --demo-users in production."
fi

if [[ "$TLS_MODE" == "self_signed" ]]; then
  cert_basename="$(sanitize_cert_name "$FQDN")"
  TLS_CERT="$CERT_DIR/$cert_basename.crt"
  TLS_KEY="$CERT_DIR/$cert_basename.key"
  if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
    log "Generating self-signed TLS certificate for $FQDN"
    san_ext="subjectAltName=DNS:$FQDN"
    if is_ipv4_address "$FQDN"; then
      san_ext="subjectAltName=IP:$FQDN"
      log "Input detected as IPv4; generating certificate with IP SAN"
    fi
    openssl req \
      -x509 \
      -newkey rsa:4096 \
      -sha256 \
      -nodes \
      -days 825 \
      -subj "/CN=$FQDN" \
      -addext "$san_ext" \
      -keyout "$TLS_KEY" \
      -out "$TLS_CERT"
    SELF_SIGNED_CERT_CREATED=1
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

service_backup_candidate="$BACKUP_DIR/nss-quarry.service.preinstall"
if backup_file_if_exists "$SERVICE_PATH" "$service_backup_candidate"; then
  SERVICE_BACKUP="$service_backup_candidate"
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

nginx_backup_candidate="$BACKUP_DIR/nss-quarry.nginx.preinstall"
if backup_file_if_exists "$NGINX_CONF" "$nginx_backup_candidate"; then
  NGINX_BACKUP="$nginx_backup_candidate"
fi

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
    client_max_body_size 6g;

    ssl_certificate $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location = /_auth_ingestor {
        internal;
        proxy_pass http://127.0.0.1:9191/authz/ingestor;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie \$http_cookie;
        proxy_set_header X-Original-URI \$request_uri;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /ingestor/ {
        auth_request /_auth_ingestor;
        proxy_pass http://127.0.0.1:9090/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;

        # Rewrite absolute dashboard API calls so embedded iframe stays under /ingestor/*.
        proxy_set_header Accept-Encoding "";
        sub_filter_once off;
        sub_filter "'/api/" "'/ingestor/api/";
    }

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

ensure_selinux_nginx_connect

log "Validating nginx config"
nginx -t

log "Reloading systemd and enabling services"
systemctl daemon-reload
systemctl enable --now nss-quarry
systemctl enable --now nginx
systemctl reload nginx

write_install_state "$STATE_FILE"

log "Install complete."
log "Service status: systemctl status nss-quarry --no-pager"
log "Health check: curl -k https://$FQDN/healthz"
log "Configured parquet root: $PARQUET_ROOT"
log "Install state saved: $STATE_FILE"
if [[ "$TLS_MODE" == "self_signed" ]]; then
  log "Note: self-signed cert installed. Replace with org-trusted certs by rerunning with TLS mode 'provided'."
fi
