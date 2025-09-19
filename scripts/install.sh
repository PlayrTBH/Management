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
SERVICE_NAME="${SERVICE_NAME:-manage-playrservers}"
APP_DOMAIN="${APP_DOMAIN:-manage.playrservers.com}"
INSTALL_NGINX="${INSTALL_NGINX:-1}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ENV_FILE="${APP_ENV_FILE:-/etc/manage-playrservers.env}"

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
    PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
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
EnvironmentFile=-${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if [[ ! -f "$ENV_FILE" ]]; then
    cat <<'EOF' > "$ENV_FILE"
# Environment overrides for the PlayrServers management API
# Set MANAGEMENT_DB_PATH if you want to move the SQLite database.
# Example:
# MANAGEMENT_DB_PATH=/var/lib/manage-playrservers/management.sqlite3
EOF
    chown "$APP_USER:$APP_GROUP" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
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
The API service is running as ${SERVICE_NAME} and listening on http://${APP_HOST}:${APP_PORT}.
If nginx is enabled, point DNS for ${APP_DOMAIN} to this host and add TLS using certbot.
EOF
