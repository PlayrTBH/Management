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

ICON_INFO="ℹ️"
ICON_OK="✅"
ICON_WARN="⚠️"
ICON_ERROR="❌"

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
DEFAULT_APP_REPO="${DEFAULT_APP_REPO:-https://github.com/PlayrTBH/Management.git}"

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

LOG_FILE="${LOG_FILE:-/var/log/manage-playrservers-install.log}"
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"

append_log() {
    printf '%s\n' "$1" >> "$LOG_FILE"
}

run_cmd() {
    append_log "==> $(printf '%q ' "$@")"
    "$@" >> "$LOG_FILE" 2>&1
}

PROGRESS_WIDTH=32
TOTAL_SECTIONS=7
if [[ "$INSTALL_NGINX" == "1" ]]; then
    TOTAL_SECTIONS=$((TOTAL_SECTIONS + 1))
fi
COMPLETED_SECTIONS=0
CURRENT_TITLE=""
PROGRESS_ACTIVE=0
MAIN_PROGRESS_LINE=""
SECTION_PROGRESS_LINE=""
SECTION_PROGRESS_WIDTH=26
CURRENT_SECTION_DESCRIPTIONS=()
CURRENT_SECTION_TOTAL=0
CURRENT_SECTION_INDEX=0

refresh_progress_display() {
    printf "\r\033[2K%s" "$MAIN_PROGRESS_LINE"
    if [[ -n "$SECTION_PROGRESS_LINE" ]]; then
        printf "\n\033[2K%s" "$SECTION_PROGRESS_LINE"
        printf "\033[1A\r"
    else
        printf "\r"
    fi
    PROGRESS_ACTIVE=1
}

progress_clear() {
    printf "\r\033[2K"
    if [[ -n "$SECTION_PROGRESS_LINE" ]]; then
        printf "\n\033[2K"
        printf "\033[1A\r"
    else
        printf "\r"
    fi
}

render_progress() {
    local completed=$1
    local display_index=$2
    local title=$3
    local total=$TOTAL_SECTIONS
    local width=$PROGRESS_WIDTH

    if (( completed > total )); then
        completed=$total
    fi

    local filled=0
    if (( total > 0 )); then
        filled=$(( completed * width / total ))
    fi

    local bar=""
    for ((i = 0; i < width; i++)); do
        if (( i < filled )); then
            bar+="#"
        elif (( i == filled && completed < total )); then
            bar+=">"
        else
            bar+="-"
        fi
    done

    local percent=0
    if (( total > 0 )); then
        percent=$(( completed * 100 / total ))
    fi

    printf -v MAIN_PROGRESS_LINE "%s[%s]%s %3d%% (%d/%d) %s%s" \
        "$CYAN$BOLD" "$bar" "$RESET" \
        "$percent" "$display_index" "$total" "$title" "$RESET"
}

render_section_progress() {
    local completed=$1
    local total=$2
    local title=$3
    local width=$SECTION_PROGRESS_WIDTH

    if (( total <= 0 )); then
        SECTION_PROGRESS_LINE=""
        return
    fi

    if (( completed > total )); then
        completed=$total
    fi

    local filled=0
    if (( total > 0 )); then
        filled=$(( completed * width / total ))
    fi

    local bar=""
    for ((i = 0; i < width; i++)); do
        if (( i < filled )); then
            bar+="#"
        elif (( i == filled && completed < total )); then
            bar+=">"
        else
            bar+="-"
        fi
    done

    local percent=0
    if (( total > 0 )); then
        percent=$(( completed * 100 / total ))
    fi

    printf -v SECTION_PROGRESS_LINE "    %s[%s]%s %3d%% (%d/%d) %s%s" \
        "$CYAN" "$bar" "$RESET" \
        "$percent" "$completed" "$total" "$title" "$RESET"
}

progress_start() {
    CURRENT_TITLE="$1"
    local display_index=$((COMPLETED_SECTIONS + 1))
    if (( display_index > TOTAL_SECTIONS )); then
        display_index=$TOTAL_SECTIONS
    fi
    render_progress "$COMPLETED_SECTIONS" "$display_index" "Installing: $CURRENT_TITLE"
    SECTION_PROGRESS_LINE=""
    CURRENT_SECTION_DESCRIPTIONS=()
    CURRENT_SECTION_TOTAL=0
    CURRENT_SECTION_INDEX=0
    refresh_progress_display
}

progress_complete() {
    COMPLETED_SECTIONS=$((COMPLETED_SECTIONS + 1))
    local display_index=$COMPLETED_SECTIONS
    render_progress "$COMPLETED_SECTIONS" "$display_index" "Completed: $CURRENT_TITLE"
    refresh_progress_display
}

progress_finish() {
    render_progress "$COMPLETED_SECTIONS" "$TOTAL_SECTIONS" "Installation complete"
    refresh_progress_display
    printf "\r\033[2K%s\n" "$MAIN_PROGRESS_LINE"
    if [[ -n "$SECTION_PROGRESS_LINE" ]]; then
        printf "\033[2K%s\n" "$SECTION_PROGRESS_LINE"
    fi
    PROGRESS_ACTIVE=0
    MAIN_PROGRESS_LINE=""
    SECTION_PROGRESS_LINE=""
}

section_define_steps() {
    CURRENT_SECTION_DESCRIPTIONS=("$@")
    CURRENT_SECTION_TOTAL=${#CURRENT_SECTION_DESCRIPTIONS[@]}
    CURRENT_SECTION_INDEX=0
    if (( CURRENT_SECTION_TOTAL > 0 )); then
        local message="Pending: ${CURRENT_SECTION_DESCRIPTIONS[0]}"
        render_section_progress 0 "$CURRENT_SECTION_TOTAL" "$message"
    else
        SECTION_PROGRESS_LINE=""
    fi
    refresh_progress_display
}

section_step() {
    if (( CURRENT_SECTION_TOTAL == 0 )); then
        "$@"
        return
    fi
    if (( CURRENT_SECTION_INDEX >= CURRENT_SECTION_TOTAL )); then
        "$@"
        return
    fi
    local desc="${CURRENT_SECTION_DESCRIPTIONS[$CURRENT_SECTION_INDEX]}"
    render_section_progress "$CURRENT_SECTION_INDEX" "$CURRENT_SECTION_TOTAL" "Processing: $desc"
    refresh_progress_display
    "$@"
    local status="Completed: $desc"
    CURRENT_SECTION_INDEX=$((CURRENT_SECTION_INDEX + 1))
    if (( CURRENT_SECTION_INDEX < CURRENT_SECTION_TOTAL )); then
        status+=" → Next: ${CURRENT_SECTION_DESCRIPTIONS[$CURRENT_SECTION_INDEX]}"
    fi
    render_section_progress "$CURRENT_SECTION_INDEX" "$CURRENT_SECTION_TOTAL" "$status"
    refresh_progress_display
}

section_progress_finish() {
    if (( CURRENT_SECTION_TOTAL > 0 )); then
        render_section_progress "$CURRENT_SECTION_TOTAL" "$CURRENT_SECTION_TOTAL" "Section complete"
    else
        SECTION_PROGRESS_LINE=""
    fi
    refresh_progress_display
    CURRENT_SECTION_DESCRIPTIONS=()
    CURRENT_SECTION_TOTAL=0
    CURRENT_SECTION_INDEX=0
}

run_section() {
    local title="$1"
    shift
    progress_start "$title"
    "$@"
    section_progress_finish
    progress_complete
}

FAILED=0
SERVICE_ACTIVE=0

on_error() {
    local line=$1
    local code=$2
    FAILED=1
    if (( PROGRESS_ACTIVE == 1 )); then
        progress_clear
        printf '\n'
        PROGRESS_ACTIVE=0
    fi
    log_error "Installation aborted (line ${line}, exit code ${code})."
    log_info "Review ${LOG_FILE} for details."
    exit "$code"
}

on_exit() {
    if (( FAILED == 0 )); then
        if (( PROGRESS_ACTIVE == 1 )); then
            printf '\n'
            PROGRESS_ACTIVE=0
        fi
        if (( SERVICE_ACTIVE == 1 )); then
            log_success "Installation complete. Service '${SERVICE_NAME}' is active."
            log_info "Management UI: http://${APP_HOST}:${APP_PORT}"
            log_info "Automation API: http://${APP_API_HOST}:${APP_API_PORT}"
            log_info "Environment overrides: ${ENV_FILE}"
            if [[ "$INSTALL_NGINX" != "1" ]]; then
                log_info "nginx configuration was skipped (INSTALL_NGINX=${INSTALL_NGINX})."
            fi
        else
            log_warn "Installation finished but the '${SERVICE_NAME}' service is not running."
            log_warn "Inspect 'journalctl -u ${SERVICE_NAME}' for additional details."
        fi
        log_info "Installer log: ${LOG_FILE}"
    fi
}

trap 'on_error ${LINENO} $?' ERR
trap on_exit EXIT

print_banner

append_log "=== PlayrServers Control Plane Installer ==="
append_log "$(date -Is)"

prepare_system_packages() {
    append_log "-- Preparing system packages"
    export DEBIAN_FRONTEND=noninteractive
    local steps=(
        "Update apt package index"
        "Install packages: ${APT_PACKAGES[*]}"
    )
    section_define_steps "${steps[@]}"
    section_step run_cmd apt-get update
    section_step run_cmd apt-get install -y "${APT_PACKAGES[@]}"
}

configure_application_account() {
    append_log "-- Configuring application account"
    local steps=(
        "Ensure system user '${APP_USER}' exists"
        "Create application directory at ${APP_DIR}"
    )
    section_define_steps "${steps[@]}"
    if ! id "$APP_USER" &>/dev/null; then
        section_step run_cmd useradd --system --create-home --home-dir "/var/lib/${SERVICE_NAME}" --shell /usr/sbin/nologin "$APP_USER"
    else
        append_log "System user ${APP_USER} already exists"
        section_step :
    fi
    section_step run_cmd mkdir -p "$APP_DIR"
}

deploy_application_code() {
    append_log "-- Deploying application code"
    if [[ -n "$APP_REPO" ]]; then
        if [[ ! -d "$APP_DIR/.git" ]]; then
            local steps=(
                "Clone repository ${APP_REPO} (branch ${APP_BRANCH})"
            )
            section_define_steps "${steps[@]}"
            section_step run_cmd git clone --branch "$APP_BRANCH" "$APP_REPO" "$APP_DIR"
        else
            local steps=(
                "Fetch updates for ${APP_REPO}"
                "Check out branch ${APP_BRANCH}"
                "Update branch ${APP_BRANCH}"
            )
            section_define_steps "${steps[@]}"
            section_step run_cmd git -C "$APP_DIR" fetch --all --tags
            section_step run_cmd git -C "$APP_DIR" checkout "$APP_BRANCH"
            section_step run_cmd git -C "$APP_DIR" pull --ff-only
        fi
    else
        if [[ -z "$PROJECT_ROOT" ]]; then
            log_error "Unable to determine project root. Set APP_REPO or run from a repository checkout."
            exit 1
        fi
        local steps=(
            "Synchronize local project files into ${APP_DIR}"
        )
        section_define_steps "${steps[@]}"
        section_step run_cmd rsync -a --delete "$PROJECT_ROOT/" "$APP_DIR/" \
            --exclude '.git' \
            --exclude '.venv' \
            --exclude '__pycache__' \
            --exclude '*.pyc'
    fi
}

bootstrap_python_environment() {
    append_log "-- Bootstrapping Python environment"
    local steps=(
        "Set ownership on ${APP_DIR}"
        "Create Python virtual environment"
        "Install Python dependencies"
        "Prepare application data directory"
    )
    section_define_steps "${steps[@]}"
    section_step run_cmd chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
    section_step run_cmd sudo -u "$APP_USER" "$PYTHON_BIN" -m venv "$APP_DIR/.venv"
    section_step run_cmd sudo -u "$APP_USER" bash -c "set -euo pipefail; source '$APP_DIR/.venv/bin/activate'; pip install --upgrade pip; pip install -r '$APP_DIR/requirements.txt'"
    section_step run_cmd install -d -m 750 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/data"
}

write_systemd_unit_file() {
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
}

configure_systemd_service() {
    append_log "-- Writing systemd service unit"
    local steps=(
        "Install systemd unit file for ${SERVICE_NAME}"
    )
    section_define_steps "${steps[@]}"
    section_step write_systemd_unit_file
}

generate_secret() {
    "$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
}

write_environment_defaults() {
    cat <<EOF > "$ENV_FILE"
# Environment overrides for the PlayrServers control plane
# Set MANAGEMENT_DB_PATH if you want to move the SQLite database.
# Example:
# MANAGEMENT_DB_PATH=/var/lib/manage-playrservers/management.sqlite3
MANAGEMENT_PUBLIC_API_URL=https://${API_DOMAIN}
MANAGEMENT_SESSION_SECRET=${SESSION_SECRET}
EOF
}

set_environment_file_permissions() {
    run_cmd chown "$APP_USER:$APP_GROUP" "$ENV_FILE"
    run_cmd chmod 640 "$ENV_FILE"
}

ensure_public_api_url() {
    if ! grep -q '^MANAGEMENT_PUBLIC_API_URL=' "$ENV_FILE"; then
        append_log "Adding MANAGEMENT_PUBLIC_API_URL to ${ENV_FILE}"
        echo "MANAGEMENT_PUBLIC_API_URL=https://${API_DOMAIN}" >> "$ENV_FILE"
    else
        append_log "MANAGEMENT_PUBLIC_API_URL already set in ${ENV_FILE}"
    fi
}

ensure_session_secret() {
    if ! grep -q '^MANAGEMENT_SESSION_SECRET=' "$ENV_FILE"; then
        append_log "Adding MANAGEMENT_SESSION_SECRET to ${ENV_FILE}"
        local secret
        secret=$(generate_secret)
        echo "MANAGEMENT_SESSION_SECRET=${secret}" >> "$ENV_FILE"
    else
        append_log "MANAGEMENT_SESSION_SECRET already set in ${ENV_FILE}"
    fi
}

verify_service_status() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        SERVICE_ACTIVE=1
        append_log "Service ${SERVICE_NAME} is active"
    else
        append_log "Service ${SERVICE_NAME} failed to start"
        return 1
    fi
}

configure_environment_file() {
    append_log "-- Configuring environment defaults"
    if [[ ! -f "$ENV_FILE" ]]; then
        SESSION_SECRET=$(generate_secret)
        local steps=(
            "Create environment override file at ${ENV_FILE}"
            "Set ownership and permissions on ${ENV_FILE}"
        )
        section_define_steps "${steps[@]}"
        section_step write_environment_defaults
        section_step set_environment_file_permissions
    else
        append_log "Environment file ${ENV_FILE} already exists"
        local steps=(
            "Ensure MANAGEMENT_PUBLIC_API_URL is defined"
            "Ensure MANAGEMENT_SESSION_SECRET is defined"
        )
        section_define_steps "${steps[@]}"
        section_step ensure_public_api_url
        section_step ensure_session_secret
    fi
}

start_services() {
    append_log "-- Starting services"
    local steps=(
        "Reload systemd daemon configuration"
        "Enable and start ${SERVICE_NAME}"
        "Verify ${SERVICE_NAME} service status"
    )
    section_define_steps "${steps[@]}"
    section_step run_cmd systemctl daemon-reload
    section_step run_cmd systemctl enable --now "$SERVICE_NAME"
    section_step verify_service_status
}

write_nginx_configuration() {
    local config_path="$1"
    cat <<EOF > "$config_path"
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
}

enable_nginx_site() {
    local config_path="$1"
    run_cmd ln -sf "$config_path" "/etc/nginx/sites-enabled/${SERVICE_NAME}.conf"
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        run_cmd rm -f /etc/nginx/sites-enabled/default
    fi
}

configure_nginx_site() {
    append_log "-- Configuring nginx"
    local NGINX_CONF="/etc/nginx/sites-available/${SERVICE_NAME}.conf"
    local steps=(
        "Write nginx site configuration to ${NGINX_CONF}"
        "Enable nginx site ${SERVICE_NAME}"
        "Validate nginx configuration"
        "Reload nginx service"
    )
    section_define_steps "${steps[@]}"
    section_step write_nginx_configuration "$NGINX_CONF"
    section_step enable_nginx_site "$NGINX_CONF"
    section_step run_cmd nginx -t
    section_step run_cmd systemctl reload nginx
}

run_section "Preparing system packages" prepare_system_packages
run_section "Configuring application account" configure_application_account
run_section "Deploying application code" deploy_application_code
run_section "Bootstrapping Python environment" bootstrap_python_environment
run_section "Writing systemd unit" configure_systemd_service
run_section "Configuring environment defaults" configure_environment_file
run_section "Starting services" start_services

if [[ "$INSTALL_NGINX" == "1" ]]; then
    run_section "Configuring nginx" configure_nginx_site
fi

progress_finish
