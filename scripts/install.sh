#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This installer must be run as root (try again with sudo)." >&2
    exit 1
fi

if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
    BOLD=$(tput bold)
    RESET=$(tput sgr0)
    CYAN=$(tput setaf 6)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    RED=$(tput setaf 1)
else
    BOLD=""
    RESET=""
    CYAN=""
    GREEN=""
    YELLOW=""
    RED=""
fi

ICON_STEP="🚀"
ICON_INFO="ℹ️"
ICON_OK="✅"
ICON_WARN="⚠️"
ICON_ERROR="❌"

log_step() {
    printf "\n%s%s%s %s%s\n" "$CYAN" "$BOLD" "$ICON_STEP" "$1" "$RESET"
}

log_info() {
    printf "%s%s %s%s\n" "$CYAN" "$ICON_INFO" "$1" "$RESET"
}

log_success() {
    printf "%s%s %s%s\n" "$GREEN" "$ICON_OK" "$1" "$RESET"
}

log_warn() {
    printf "%s%s %s%s\n" "$YELLOW" "$ICON_WARN" "$1" "$RESET"
}

log_error() {
    printf "%s%s %s%s\n" "$RED" "$ICON_ERROR" "$1" "$RESET"
}

print_banner() {
    printf "\n%s%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n" "$CYAN" "$BOLD" "$RESET"
    printf "%s%s┃   PlayrServers Control Plane Installer   ┃%s\n" "$CYAN" "$BOLD" "$RESET"
    printf "%s%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n" "$CYAN" "$BOLD" "$RESET"
}

APP_USER="${APP_USER:-playrmanager}"
APP_GROUP="$APP_USER"
APP_DIR="${APP_DIR:-/opt/manage.playrservers}"
APP_REPO="${APP_REPO:-}"
APP_BRANCH="${APP_BRANCH:-main}"
APP_PORT="${APP_PORT:-8000}"
APP_HOST="${APP_HOST:-0.0.0.0}"
APP_API_PORT="${APP_API_PORT:-8001}"
APP_API_HOST="${APP_API_HOST:-$APP_HOST}"
SERVICE_NAME="${SERVICE_NAME:-manage-playrservers}"
APP_DOMAIN="${APP_DOMAIN:-manage.playrservers.com}"
API_DOMAIN="${API_DOMAIN:-api.playrservers.com}"
INSTALL_NGINX="${INSTALL_NGINX:-1}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ENV_FILE="${APP_ENV_FILE:-/etc/manage-playrservers.env}"
DEFAULT_APP_REPO="${DEFAULT_APP_REPO:-https://github.com/PlayrServers/Management.git}"

SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
PROJECT_ROOT=""
if [[ -n "$SCRIPT_SOURCE" ]]; then
    SCRIPT_DIR=$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd -P)
    PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
fi

if [[ -z "$APP_REPO" ]]; then
    if [[ -n "$PROJECT_ROOT" && -d "$PROJECT_ROOT/.git" ]]; then
        APP_REPO=""
    else
        APP_REPO="$DEFAULT_APP_REPO"
    fi
fi

APT_PACKAGES=(python3 python3-venv python3-pip git rsync)
if [[ "$INSTALL_NGINX" == "1" ]]; then
    APT_PACKAGES+=(nginx)
fi

FAILED=0

on_error() {
    local line=$1
    local code=$2
    FAILED=1
    log_error "Installation aborted (line ${line}, exit code ${code})."
    exit "$code"
}

on_exit() {
    if [[ $FAILED -eq 0 ]]; then
        log_success "Installation complete. Service '${SERVICE_NAME}' is active."
        log_info "Management UI: http://${APP_HOST}:${APP_PORT}"
        log_info "API endpoint: http://${APP_API_HOST}:${APP_API_PORT}"
        log_info "Environment overrides: ${ENV_FILE}"
        log_info "Expose https://${APP_DOMAIN} and https://${API_DOMAIN} via your reverse proxy."
    fi
}

trap 'on_error ${LINENO} $?' ERR
trap on_exit EXIT

print_banner

log_step "Preparing system packages"
export DEBIAN_FRONTEND=noninteractive
log_info "Updating apt repositories"
apt-get update
log_info "Installing packages: ${APT_PACKAGES[*]}"
apt-get install -y "${APT_PACKAGES[@]}"
log_success "System dependencies installed."

log_step "Configuring application account"
if ! id "$APP_USER" &>/dev/null; then
    log_info "Creating system user ${APP_USER}"
    useradd --system --create-home --home-dir "/var/lib/${SERVICE_NAME}" --shell /usr/sbin/nologin "$APP_USER"
else
    log_info "System user ${APP_USER} already exists"
fi
log_info "Ensuring application directory ${APP_DIR}"
mkdir -p "$APP_DIR"
log_success "Account ready."

log_step "Deploying application code"
if [[ -n "$APP_REPO" ]]; then
    log_info "Syncing from Git repository ${APP_REPO} (branch ${APP_BRANCH})"
    if [[ ! -d "$APP_DIR/.git" ]]; then
        git clone --branch "$APP_BRANCH" "$APP_REPO" "$APP_DIR"
    else
        git -C "$APP_DIR" fetch --all --tags
        git -C "$APP_DIR" checkout "$APP_BRANCH"
        git -C "$APP_DIR" pull --ff-only
    fi
else
    if [[ -z "$PROJECT_ROOT" ]]; then
        log_error "Unable to determine project root. Set APP_REPO or run from a repository checkout."
        exit 1
    fi
    log_info "Copying local checkout from ${PROJECT_ROOT}"
    rsync -a --delete "$PROJECT_ROOT/" "$APP_DIR/" \
        --exclude '.git' \
        --exclude '.venv' \
        --exclude '__pycache__' \
        --exclude '*.pyc'
fi
log_success "Application synced to ${APP_DIR}."

log_step "Bootstrapping Python environment"
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
log_info "Creating virtual environment"
sudo -u "$APP_USER" "$PYTHON_BIN" -m venv "$APP_DIR/.venv"
log_info "Installing Python dependencies"
sudo -u "$APP_USER" bash -c "set -euo pipefail; source '$APP_DIR/.venv/bin/activate'; pip install --upgrade pip; pip install -r '$APP_DIR/requirements.txt'"
install -d -m 750 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/data"
log_success "Python environment ready."

log_step "Configuring systemd service"
cat <<EOF > "/etc/systemd/system/${SERVICE_NAME}.service"
[Unit]
Description=PlayrServers management API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
Environment=MANAGEMENT_PORT=${APP_PORT}
Environment=MANAGEMENT_HOST=${APP_HOST}
Environment=MANAGEMENT_API_PORT=${APP_API_PORT}
Environment=MANAGEMENT_API_HOST=${APP_API_HOST}
EnvironmentFile=-${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

generate_secret() {
    "$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
}

if [[ ! -f "$ENV_FILE" ]]; then
    log_info "Creating environment file ${ENV_FILE}"
    SESSION_SECRET=$(generate_secret)
    cat <<EOF > "$ENV_FILE"
# Environment overrides for the PlayrServers control plane
# Set MANAGEMENT_DB_PATH if you want to move the SQLite database.
# Example:
# MANAGEMENT_DB_PATH=/var/lib/manage-playrservers/management.sqlite3
MANAGEMENT_PUBLIC_API_URL=https://${API_DOMAIN}
MANAGEMENT_SESSION_SECRET=${SESSION_SECRET}
EOF
    chown "$APP_USER:$APP_GROUP" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
else
    log_info "Updating environment file ${ENV_FILE}"
    if ! grep -q '^MANAGEMENT_PUBLIC_API_URL=' "$ENV_FILE"; then
        echo "MANAGEMENT_PUBLIC_API_URL=https://${API_DOMAIN}" >> "$ENV_FILE"
    fi
    if ! grep -q '^MANAGEMENT_SESSION_SECRET=' "$ENV_FILE"; then
        SESSION_SECRET=$(generate_secret)
        echo "MANAGEMENT_SESSION_SECRET=${SESSION_SECRET}" >> "$ENV_FILE"
    fi
fi

log_info "Reloading systemd units"
systemctl daemon-reload
log_info "Enabling and starting ${SERVICE_NAME}"
systemctl enable --now "$SERVICE_NAME"
log_success "Systemd service configured."

if [[ "$INSTALL_NGINX" == "1" ]]; then
    log_step "Configuring nginx reverse proxy"
    NGINX_CONF="/etc/nginx/sites-available/${SERVICE_NAME}.conf"
    cat <<EOF > "$NGINX_CONF"
server {
    listen 80;
    server_name ${APP_DOMAIN};

    location / {
        proxy_pass http://${APP_HOST}:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 80;
    server_name ${API_DOMAIN};

    location / {
        proxy_pass http://${APP_API_HOST}:${APP_API_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/${SERVICE_NAME}.conf"
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    log_info "Validating nginx configuration"
    nginx -t
    log_info "Reloading nginx"
    systemctl reload nginx
    log_success "nginx configuration applied."
else
    log_warn "Skipping nginx configuration (INSTALL_NGINX=0)."
fi
