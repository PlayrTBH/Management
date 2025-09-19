#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This updater must be run as root (try again with sudo)." >&2
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
    printf "%s%s %s%s%s\n" "$CYAN" "$ICON_INFO" "$BOLD" "$1" "$RESET"
}

log_success() {
    printf "%s%s %s%s%s\n" "$GREEN" "$ICON_OK" "$BOLD" "$1" "$RESET"
}

log_warn() {
    printf "%s%s %s%s%s\n" "$YELLOW" "$ICON_WARN" "$BOLD" "$1" "$RESET"
}

log_error() {
    printf "%s%s %s%s%s\n" "$RED" "$ICON_ERROR" "$BOLD" "$1" "$RESET" >&2
}

APP_DIR="${APP_DIR:-/opt/manage.playrservers}"
APP_BRANCH="${APP_BRANCH:-main}"
APP_REMOTE="${APP_REMOTE:-origin}"
SERVICE_NAME="${SERVICE_NAME:-manage-playrservers}"
VENV_PATH="${VENV_PATH:-$APP_DIR/.venv}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$APP_DIR/requirements.txt}"
STOP_SERVICE="${STOP_SERVICE:-1}"
SKIP_SERVICE_RESTART="${SKIP_SERVICE_RESTART:-0}"

SERVICE_WAS_ACTIVE=0
SERVICE_STOPPED=0

cleanup() {
    local exit_code=$?
    if (( exit_code != 0 )) && (( SERVICE_STOPPED == 1 )) && command -v systemctl >/dev/null 2>&1; then
        if [[ "$SKIP_SERVICE_RESTART" != "1" ]]; then
            log_warn "Update failed; attempting to restart ${SERVICE_NAME}."
            if systemctl start "$SERVICE_NAME"; then
                log_info "${SERVICE_NAME} has been restarted after a failed update."
            else
                log_error "Unable to restart ${SERVICE_NAME}. Review 'journalctl -u ${SERVICE_NAME}' for details."
            fi
        fi
    fi
}
trap cleanup EXIT

log_info "Updating PlayrServers Control Plane in ${APP_DIR}"

if [[ ! -d "$APP_DIR/.git" ]]; then
    log_error "No Git repository found in ${APP_DIR}."
    exit 1
fi

if [[ -n $(git -C "$APP_DIR" status --porcelain) ]]; then
    log_error "Repository has uncommitted changes. Commit or stash them before updating."
    exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [[ "$STOP_SERVICE" == "1" ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping ${SERVICE_NAME} service."
        systemctl stop "$SERVICE_NAME"
        SERVICE_WAS_ACTIVE=1
        SERVICE_STOPPED=1
    else
        log_info "Service ${SERVICE_NAME} is not active."
    fi
fi

CURRENT_REV=$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
log_info "Current revision: ${CURRENT_REV}"

log_info "Fetching ${APP_REMOTE}/${APP_BRANCH}"
git -C "$APP_DIR" fetch "$APP_REMOTE"
git -C "$APP_DIR" checkout "$APP_BRANCH"
git -C "$APP_DIR" pull --ff-only "$APP_REMOTE" "$APP_BRANCH"

NEW_REV=$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
if [[ "$NEW_REV" == "$CURRENT_REV" ]]; then
    log_info "Repository already up to date (revision ${NEW_REV})."
else
    log_success "Repository updated to revision ${NEW_REV}."
fi

if [[ -x "$VENV_PATH/bin/pip" ]]; then
    log_info "Updating Python dependencies."
    "$VENV_PATH/bin/pip" install --upgrade pip
    "$VENV_PATH/bin/pip" install -r "$REQUIREMENTS_FILE"
else
    log_warn "Virtual environment not found at ${VENV_PATH}; skipping dependency update."
fi

if command -v systemctl >/dev/null 2>&1 && [[ "$SKIP_SERVICE_RESTART" != "1" ]]; then
    log_info "Reloading systemd units."
    systemctl daemon-reload
    if (( SERVICE_WAS_ACTIVE == 1 )); then
        log_info "Starting ${SERVICE_NAME} service."
        systemctl start "$SERVICE_NAME"
        SERVICE_STOPPED=0
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_success "${SERVICE_NAME} is running."
        else
            log_warn "${SERVICE_NAME} did not start successfully. Check 'journalctl -u ${SERVICE_NAME}'."
        fi
    else
        log_info "Service ${SERVICE_NAME} was not active before the update; leaving it stopped."
    fi
else
    log_warn "Systemd not available or restart skipped. Start ${SERVICE_NAME} manually if required."
fi

log_success "Update completed."
