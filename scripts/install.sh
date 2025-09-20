#!/usr/bin/env bash
#
# Bootstrap installer for the PlayrServers management service.
#
# This script is designed to be downloaded and executed directly, for example:
#   curl -fsSL https://raw.githubusercontent.com/PlayrTBH/Management/main/scripts/install.sh | sudo bash
#
# It will ensure required system packages are available, clone or update the
# repository, create an isolated Python virtual environment, and finally invoke
# scripts/install_service.py to install Python dependencies, initialise the
# database, and optionally create the first administrator account.

set -euo pipefail

REPO_URL=${MANAGEMENT_REPO_URL:-"https://github.com/PlayrTBH/Management.git"}
BRANCH=${MANAGEMENT_BRANCH:-"main"}
INSTALL_DIR=${MANAGEMENT_INSTALL_DIR:-"/opt/playr-management"}
VENV_DIR=${MANAGEMENT_VENV_DIR:-"${INSTALL_DIR}/.venv"}
PYTHON_BIN=${MANAGEMENT_PYTHON_BIN:-"python3"}

log() {
    printf '\n[playrservers] %s\n' "$1"
}

warn() {
    printf '\n[playrservers][warning] %s\n' "$1" >&2
}

die() {
    printf '\n[playrservers][error] %s\n' "$1" >&2
    exit 1
}

print_usage() {
    cat <<USAGE
Usage: bash install.sh [options forwarded to scripts/install_service.py]

Environment overrides:
  MANAGEMENT_INSTALL_DIR   Installation directory (default: ${INSTALL_DIR})
  MANAGEMENT_VENV_DIR      Python virtual environment path (default: ${VENV_DIR})
  MANAGEMENT_BRANCH        Git branch or tag to install (default: ${BRANCH})
  MANAGEMENT_REPO_URL      Repository URL (default: ${REPO_URL})
  MANAGEMENT_PYTHON_BIN    Python interpreter to use (default: ${PYTHON_BIN})

Any additional command-line arguments are passed verbatim to
scripts/install_service.py. Refer to that script for supported options such as
--admin-name, --admin-email, and --admin-password when running non-interactively.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_usage
    exit 0
fi

run_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            die "Root privileges are required to run '$*'. Please re-run this script as root or with sudo."
        fi
    fi
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

ensure_system_dependencies() {
    local needs_packages=0
    have_command git || needs_packages=1

    if ! have_command "$PYTHON_BIN"; then
        needs_packages=1
    else
        if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
            needs_packages=1
        fi
    fi

    if [[ $needs_packages -eq 0 ]]; then
        log "System dependencies already satisfied."
        return
    fi

    if have_command apt-get; then
        log "Installing system dependencies via apt-get"
        run_root apt-get update -y
        run_root apt-get install -y git python3 python3-venv python3-pip
    elif have_command dnf; then
        log "Installing system dependencies via dnf"
        run_root dnf install -y git python3 python3-pip
    elif have_command yum; then
        log "Installing system dependencies via yum"
        run_root yum install -y git python3 python3-pip
    elif have_command zypper; then
        log "Installing system dependencies via zypper"
        run_root zypper --non-interactive install git python3 python3-pip
    elif have_command pacman; then
        log "Installing system dependencies via pacman"
        run_root pacman -Sy --noconfirm git python
    elif have_command apk; then
        log "Installing system dependencies via apk"
        run_root apk add --no-cache git python3 py3-pip py3-venv
    elif have_command brew; then
        log "Installing system dependencies via Homebrew"
        brew install git python || brew upgrade git python
    else
        warn "Unable to detect a supported package manager. Ensure git, python3, and the python venv module are installed before re-running."
    fi

    have_command git || die "git is required but was not installed automatically."

    if ! have_command "$PYTHON_BIN"; then
        die "${PYTHON_BIN} is required but was not installed automatically."
    fi

    if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
        die "${PYTHON_BIN} does not provide the venv module. Install the python3-venv package (or equivalent) and retry."
    fi
}

prepare_checkout() {
    local parent_dir
    parent_dir=$(dirname "${INSTALL_DIR}")
    run_root mkdir -p "${parent_dir}"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log "Updating existing repository at ${INSTALL_DIR}"
        run_root git -C "${INSTALL_DIR}" fetch --depth 1 origin "${BRANCH}"
        run_root git -C "${INSTALL_DIR}" checkout "${BRANCH}"
        run_root git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
    elif [[ -e "${INSTALL_DIR}" ]]; then
        die "${INSTALL_DIR} exists but is not a git repository. Remove it or set MANAGEMENT_INSTALL_DIR to a different path."
    else
        log "Cloning ${REPO_URL} into ${INSTALL_DIR}"
        run_root git clone --branch "${BRANCH}" --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
    fi

    if [[ -n "${SUDO_UID:-}" ]]; then
        run_root chown -R "${SUDO_UID}:${SUDO_GID}" "${INSTALL_DIR}"
    fi
}

create_virtualenv() {
    log "Creating Python virtual environment at ${VENV_DIR}"
    "$PYTHON_BIN" -m venv "${VENV_DIR}"

    if [[ ! -x "${VENV_DIR}/bin/pip" ]]; then
        if ! "${VENV_DIR}/bin/python" -m ensurepip --upgrade >/dev/null 2>&1; then
            warn "ensurepip is unavailable; continuing without upgrading pip explicitly."
        fi
    fi

    if [[ -x "${VENV_DIR}/bin/pip" ]]; then
        "${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel
    else
        die "pip is not available inside ${VENV_DIR}. Install Python with ensurepip support and retry."
    fi
}

run_python_installer() {
    log "Running management installer"
    cd "${INSTALL_DIR}"
    "${VENV_DIR}/bin/python" scripts/install_service.py "$@"
}

main() {
    ensure_system_dependencies
    prepare_checkout
    create_virtualenv
    run_python_installer "$@"

    cat <<EOM

[playrservers] Installation complete.
The service files are located at: ${INSTALL_DIR}
To activate the environment, run: source "${VENV_DIR}/bin/activate"
Start the API with: "${VENV_DIR}/bin/python" "${INSTALL_DIR}/main.py" serve --host 0.0.0.0 --port 8000
EOM
}

main "$@"
