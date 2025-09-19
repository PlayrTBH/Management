#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This installer must be run as root (try again with sudo)." >&2
    exit 1
fi

APP_USER="${APP_USER:-playrmanager}"
APP_GROUP="$APP_USER"
APP_DIR="${APP_DIR:-/opt/manage.playrservers}"
APP_REPO="${APP_REPO:-}"
APP_BRANCH="${APP_BRANCH:-main}"
APP_PORT="${APP_PORT:-8000}"
APP_HOST="${APP_HOST:-127.0.0.1}"
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

apt-get update
apt-get install -y "${APT_PACKAGES[@]}"

if ! id "$APP_USER" &>/dev/null; then
    useradd --system --create-home --home-dir "/var/lib/${SERVICE_NAME}" --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$APP_DIR"

if [[ -n "$APP_REPO" ]]; then
    if [[ ! -d "$APP_DIR/.git" ]]; then
        git clone --branch "$APP_BRANCH" "$APP_REPO" "$APP_DIR"
    else
        git -C "$APP_DIR" fetch --all --tags
        git -C "$APP_DIR" checkout "$APP_BRANCH"
        git -C "$APP_DIR" pull --ff-only
    fi
else
    if [[ -z "$PROJECT_ROOT" ]]; then
        echo "Unable to determine project root. Set APP_REPO to a Git URL or run the installer from a repository checkout." >&2
        exit 1
    fi
    rsync -a --delete "$PROJECT_ROOT/" "$APP_DIR/" \
        --exclude '.git' \
        --exclude '.venv' \
        --exclude '__pycache__' \
        --exclude '*.pyc'
fi

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

sudo -u "$APP_USER" "$PYTHON_BIN" -m venv "$APP_DIR/.venv"
sudo -u "$APP_USER" bash -c "set -euo pipefail; source '$APP_DIR/.venv/bin/activate'; pip install --upgrade pip; pip install -r '$APP_DIR/requirements.txt'"

install -d -m 750 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/data"

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
    if ! grep -q '^MANAGEMENT_PUBLIC_API_URL=' "$ENV_FILE"; then
        echo "MANAGEMENT_PUBLIC_API_URL=https://${API_DOMAIN}" >> "$ENV_FILE"
    fi
    if ! grep -q '^MANAGEMENT_SESSION_SECRET=' "$ENV_FILE"; then
        SESSION_SECRET=$(generate_secret)
        echo "MANAGEMENT_SESSION_SECRET=${SESSION_SECRET}" >> "$ENV_FILE"
    fi
fi

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

if [[ "$INSTALL_NGINX" == "1" ]]; then
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
    nginx -t
    systemctl reload nginx
fi

cat <<EOF
Installation complete.
The management services are running as ${SERVICE_NAME}.
- Management UI: http://${APP_HOST}:${APP_PORT}
- API endpoint: http://${APP_API_HOST}:${APP_API_PORT}
Expose https://${APP_DOMAIN} for the operator UI and forward https://${API_DOMAIN} to http://${APP_API_HOST}:${APP_API_PORT} via Cloudflare or nginx.
Remember to provision TLS certificates for both hostnames.
EOF
