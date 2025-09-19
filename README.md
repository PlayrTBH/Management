# PlayrServers QEMU Management Portal

A hardened FastAPI application that exposes a web API for orchestrating remote
QEMU/KVM hypervisors. The service is designed to run at
**https://manage.playrservers.com** and only exposes a control-plane web
interface – no virtualization workloads run on this host. Remote hypervisors
install a lightweight agent that authenticates with this application using a
user-scoped API key. Each user owns their agents, SSH credentials, and audit
history; no sensitive material is shared across accounts.

## Key Features

- 🔐 **Per-user API keys** – operators create a profile and receive a unique API
  key which is required in the `Authorization: Bearer <key>` header.
- 🔑 **User-scoped SSH keys** – private keys are stored per agent and never
  exposed outside of the owning profile.
- 🌐 **Remote-only control** – the web tier never installs QEMU/libvirt; it only
  talks to remote servers that already provide virtualization.
- 📋 **Agent registry** – users can register multiple agents (remote hosts)
  including hostnames, SSH ports, and host verification preferences.
- 🧠 **VM lifecycle API** – trigger `start`, `shutdown`, `destroy`, `reboot`, or
  `dominfo` via secure HTTP calls.
- 🗄️ **SQLite persistence** – all profiles, agents, and keys are stored locally
  in `data/management.sqlite3` by default.

## Quick start on Ubuntu 24.04

Run the installer with a **single command** on a fresh Ubuntu 24.04 server. The
script installs system dependencies, provisions a Python virtual environment,
creates a systemd service, and (optionally) configures nginx as a reverse
proxy for `manage.playrservers.com`.

```bash
sudo ./scripts/install.sh
```

> 💡 To install directly from a Git host, publish this repository and execute:
> `curl -fsSL https://raw.githubusercontent.com/<your-account>/Management/main/scripts/install.sh | sudo bash`
> (replace the URL with your Git remote).

Environment variables can tweak the installer without editing the script:

- `APP_REPO` – clone/pull from a Git URL instead of copying the current
  directory.
- `APP_DIR` – installation directory (default `/opt/manage.playrservers`).
- `APP_DOMAIN` – nginx server name (default `manage.playrservers.com`).
- `APP_PORT` – internal uvicorn port (default `8000`).
- `INSTALL_NGINX` – set to `0` to skip nginx installation.

After installation the API runs as the `manage-playrservers` systemd unit and
listens on `http://127.0.0.1:8000` (proxied by nginx to port 80). Adjust DNS so
that `manage.playrservers.com` resolves to the host and obtain TLS certificates
(e.g., with certbot).

## Configuration

The application stores its data in SQLite and exposes configuration through
environment variables:

| Environment Variable      | Description                                                   | Default                        |
| ------------------------- | ------------------------------------------------------------- | ------------------------------ |
| `MANAGEMENT_DB_PATH`      | Custom path to the SQLite database                            | `data/management.sqlite3`      |
| `MANAGEMENT_HOST`         | Bind address for uvicorn                                      | `0.0.0.0`                      |
| `MANAGEMENT_PORT`         | Listen port for uvicorn                                       | `8000`                         |
| `MANAGEMENT_WORKERS`      | Number of uvicorn worker processes                            | `1`                            |
| `MANAGEMENT_RELOAD`       | Set to `true`/`1` to enable auto-reload (development only)    | `false`                        |

The systemd unit installed by `scripts/install.sh` sources `/etc/manage-playrservers.env`
(if present) so you can persist environment overrides there.

## API Overview

All endpoints, except `/health` and `POST /users`, require authentication with
an API key via the `Authorization: Bearer <key>` header.

### Health

| Method | Path      | Description            |
| ------ | --------- | ---------------------- |
| GET    | `/health` | Service readiness ping |

### User & API key management

| Method | Path                     | Description                                    |
| ------ | ------------------------ | ---------------------------------------------- |
| POST   | `/users`                 | Create a user profile and receive an API key   |
| GET    | `/users/me`              | Return the authenticated user's profile        |
| POST   | `/users/me/api-key/rotate` | Issue a new API key for the current user      |

Example user creation:

```bash
curl -X POST https://manage.playrservers.com/users \
  -H 'Content-Type: application/json' \
  -d '{"name": "alice", "email": "alice@example.com"}'
```

The response includes the plaintext `api_key` value (store it securely – it is
not shown again).

### Agent registry

| Method | Path                               | Description                                   |
| ------ | ---------------------------------- | --------------------------------------------- |
| GET    | `/agents`                          | List the caller's registered agents           |
| POST   | `/agents`                          | Register a new agent / virtualization host    |
| GET    | `/agents/{id}`                     | Retrieve metadata for a specific agent        |
| GET    | `/agents/{id}/credentials`         | Retrieve the agent's stored SSH key material  |
| PATCH  | `/agents/{id}`                     | Update agent metadata or credentials          |
| DELETE | `/agents/{id}`                     | Remove an agent                               |

Agent registration payload example:

```bash
curl -X POST https://manage.playrservers.com/agents \
  -H 'Authorization: Bearer <api-key>' \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "dalek-hypervisor",
        "hostname": "192.0.2.15",
        "port": 22,
        "username": "qemu-admin",
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n",
        "allow_unknown_hosts": false
      }'
```

### VM lifecycle operations

All VM operations are scoped to an agent identifier and require authentication.
Responses include the executed command, exit status, stdout, and stderr.

| Method | Path                                                | Description                         |
| ------ | --------------------------------------------------- | ----------------------------------- |
| GET    | `/agents/{id}/vms`                                  | List VMs visible to the agent       |
| GET    | `/agents/{id}/vms/{vm}`                             | `virsh dominfo` for a VM            |
| POST   | `/agents/{id}/vms/{vm}/start`                       | Start a VM                          |
| POST   | `/agents/{id}/vms/{vm}/shutdown`                    | Gracefully shut down a VM           |
| POST   | `/agents/{id}/vms/{vm}/force-stop`                  | Force stop (`virsh destroy`)        |
| POST   | `/agents/{id}/vms/{vm}/reboot`                      | Reboot a VM                         |

## Operational Notes

- Ensure SSH private keys uploaded to the portal are dedicated to the target
  hypervisors and protected with strong passphrases.
- The management host does **not** install QEMU/libvirt. Agents run on the
  virtualization servers themselves and expose access over SSH to `virsh`.
- Deploy behind TLS (nginx + certbot or another reverse proxy) to protect API
  credentials in transit.
- Restrict network access to the management host; this portal is for personal
  use and is not meant for a public audience.
- Back up `data/management.sqlite3` regularly to preserve user profiles and
  agent definitions.

## Development

Create a virtual environment and install requirements locally:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
MANAGEMENT_RELOAD=true MANAGEMENT_PORT=8000 python main.py
```

Use the `/users` endpoint to create a profile, set the `Authorization` header in
subsequent requests, and register agents that point to your lab hypervisors.
