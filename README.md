# PlayrServers Management (Reboot)

The management control plane is being rebuilt from the ground up. All legacy
code related to the automation API, hypervisor management, pairing flows, and
the previous FastAPI application has been removed. This repository now focuses
solely on the persistent data layer so that the next iteration can grow on a
clean foundation.

## Current state

- ✅ **SQLite-backed user storage** – `app.database.Database` persists user
  accounts with hashed passwords. Optional dependencies such as `passlib` remain
  optional; the module provides a PBKDF2 fallback when they are absent.
- ✅ **Agent coordination service** – `app.service.create_app()` exposes a
  FastAPI application that agents use to authenticate, maintain heartbeats, and
  request encrypted tunnels that terminate on `api.playrservers.com:443`.
- ✅ **Secure web dashboard** – administrators can sign in at
  `https://<host>/` to review their account and view paired hypervisors.
- ✅ **Command-line bootstrap** – `python main.py` initialises the database by
  default, while `python main.py serve` launches the HTTP control plane.

## Getting started

### Automated installation

Fetch and execute the remote installer to provision the management service and
its dependencies in one command:

```bash
curl -fsSL https://raw.githubusercontent.com/PlayrTBH/Management/main/scripts/install.sh | sudo bash
```

You can forward flags to the underlying Python installer (for unattended
setups) by appending them after `--`:

```bash
curl -fsSL https://raw.githubusercontent.com/PlayrTBH/Management/main/scripts/install.sh \
  | sudo bash -s -- --admin-name "Service Admin" --admin-email admin@example.com --admin-password "your-strong-password"
```

Override the default install path or branch via environment variables such as
`MANAGEMENT_INSTALL_DIR=/srv/management`. These values are documented at the top
of `scripts/install.sh`.

If you've already cloned the repository locally, run the installer script to
install dependencies, initialise the database, and create the first user
account:

```bash
python scripts/install_service.py
```

Use `--skip-deps` if you prefer to manage Python packages yourself. When the
script completes you can start the API with `python main.py serve`.

To run the installer without interactive prompts, provide the initial account
details via flags:

```bash
python scripts/install_service.py \
  --admin-name "Service Admin" \
  --admin-email admin@example.com \
  --admin-password "your-strong-password"
```

All three options must be supplied together, and the password must be at least
12 characters long.

### Hypervisor agent deployment

The management interface exposes a ready-made installer for remote hypervisors
at `https://<host>/agent`. Execute it directly on a supported Ubuntu system to
provision QEMU, libvirt, and the PlayrServers agent runtime:

```bash
curl -fsSL https://<host>/agent | sudo bash
```

Generate an API key for the agent from the web dashboard's **Agent installer**
page or use the bundled helper and supply it to the installer when prompted:

```bash
python scripts/create_api_key.py admin@example.com --name "DC-1 hypervisor"
curl -fsSL https://<host>/agent | sudo bash -s -- --api-key psm_xxxxx --agent-id hypervisor-01
```

Agents authenticate back to the management plane using this API key, install
their own systemd service, and maintain an encrypted reverse tunnel to
`api.playrservers.com` so the dashboard can expose web-based SSH sessions and
issue VM management commands.

### Manual setup

Create a virtual environment and install the web-service dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Initialise the database and create a test user:

```bash
python main.py
python scripts/create_user.py "Test User" test@example.com
```

### Running the management API

Launch the management service using the same credentials you created above.
Provide the path to your TLS certificate and private key so the agent API
listens on port 8001 while the web dashboard is exposed on port 443:

```bash
python main.py serve \
  --api-host 0.0.0.0 \
  --api-port 8001 \
  --web-host 0.0.0.0 \
  --web-port 443 \
  --ssl-certfile /etc/ssl/certs/management.crt \
  --ssl-keyfile /etc/ssl/private/management.key
```

When using `scripts/install.sh` or `scripts/install_service.py` without
explicit TLS arguments the installer automatically provisions a self-signed
certificate stored under `data/tls/`. The generated systemd unit references the
certificate and key so both the API (port 8001) and dashboard (port 443) are
reachable over HTTPS; replace the files with a certificate issued by a trusted
authority for production deployments.

With the service running you can sign in at `https://localhost/` (or the
appropriate hostname) to access the new management dashboard. The JSON API
remains available at `https://localhost:8001/`. Sessions are kept in-memory on
the server, so restarting the process will invalidate any active browser
logins.

Agents authenticate with HTTP Basic credentials (email + password) and interact
with the following key endpoints:

- `POST /v1/agents/connect` – register an agent and obtain session/tunnel tokens
- `POST /v1/agents/{agent_id}/heartbeat` – keep the session alive and update
  tunnel states
- `POST /v1/agents/{agent_id}/tunnels` – request an authenticated tunnel for SSH
  or command execution without exposing additional ports
- `POST /v1/agents/{agent_id}/tunnels/{tunnel_id}/close` – terminate a tunnel
- `GET /v1/agents/{agent_id}` – retrieve detailed session and tunnel metadata

The API always advertises the public endpoint `api.playrservers.com:443` to
agents. Custom host/port values can be supplied at runtime using the
`--tunnel-host` and `--tunnel-port` flags if you need to point at staging
infrastructure.

## Development

Pytest drives the remaining unit tests:

```bash
pytest
```

The goal for this phase is simply to provide a trustworthy persistence layer
while the new management and API experiences are designed. Feel free to iterate
on the database schema and supporting utilities before larger application
components return.
