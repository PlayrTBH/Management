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
  request encrypted tunnels that terminate on `manage.playrservers.com:443`.
- ✅ **Command-line bootstrap** – `python main.py` initialises the database by
  default, while `python main.py serve` launches the HTTP control plane.

## Getting started

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

Launch the API using the same credentials you created above:

```bash
python main.py serve --host 0.0.0.0 --port 8000
```

Agents authenticate with HTTP Basic credentials (email + password) and interact
with the following key endpoints:

- `POST /v1/agents/connect` – register an agent and obtain session/tunnel tokens
- `POST /v1/agents/{agent_id}/heartbeat` – keep the session alive and update
  tunnel states
- `POST /v1/agents/{agent_id}/tunnels` – request an authenticated tunnel for SSH
  or command execution without exposing additional ports
- `POST /v1/agents/{agent_id}/tunnels/{tunnel_id}/close` – terminate a tunnel
- `GET /v1/agents/{agent_id}` – retrieve detailed session and tunnel metadata

The API always advertises the public endpoint `manage.playrservers.com:443` to
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
