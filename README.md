# PlayrServers QEMU Management Portal (Assume this is garbage, do not use)

A hardened FastAPI application that exposes both a password-protected operator
portal and a machine-to-machine API for orchestrating remote QEMU/KVM
hypervisors. The management UI lives at **https://manage.playrservers.com** and
the automation API at **https://api.playrservers.com**, both operated by the
PlayrServers control plane team. Remote hypervisors run a lightweight agent that
authenticates with this application using a user-scoped API key issued through
the management interface. Each operator owns their agents, SSH credentials, and
audit history; no sensitive material is shared across accounts. Operators using
the portal focus on onboarding hypervisors and agents—the hosting
infrastructure is maintained separately by the platform team.

## Key Features

- 🔒 **Password-protected operator portal** – administrators provision accounts
  and operators authenticate via the management UI; self-service registration is
  disabled by default.
- 🔐 **Per-user API keys** – rotate or revoke automation tokens from the portal;
  requests must include the `Authorization: Bearer <key>` header.
- 🔑 **User-scoped SSH keys** – each profile receives a unique provisioning
  key pair and private keys are never exposed outside of the owning account.
- 🌐 **Remote-only control** – the web tier never installs QEMU/libvirt; it only
  talks to remote servers that already provide virtualization.
- 📋 **Agent registry** – users can register multiple agents (remote hosts)
  including hostnames, SSH ports, and host verification preferences.
- 🧠 **VM lifecycle API** – trigger `start`, `shutdown`, `destroy`, `reboot`, or
  `dominfo` via secure HTTP calls.
- 🧰 **Guided VM deployments** – bootstrap Ubuntu 24.04 LTS and Windows Server
  2022 guests remotely, complete with default automation credentials.
- 🗄️ **SQLite persistence** – all profiles, agents, and keys are stored locally
  in `data/management.sqlite3` by default.

## Quick start on Ubuntu 24.04

Run the installer with a **single command** on a fresh Ubuntu 24.04 server. The
script installs system dependencies, provisions a Python virtual environment,
creates a systemd service, and (optionally) configures nginx to publish the
management and API endpoints. The CLI emits colorised status banners so you
can track progress at a glance.

```bash
curl -fsSL https://raw.githubusercontent.com/PlayrTBH/Management/main/scripts/install.sh | sudo bash
```

Already have a clone checked out? Run the same installer locally:

```bash
sudo ./scripts/install.sh
```

Environment variables can tweak the installer without editing the script:

- `APP_REPO` – clone/pull from a Git URL instead of copying the current
  directory.
- `APP_DIR` – installation directory (default `/opt/manage.playrservers`).
- `APP_DOMAIN` – public hostname for the management UI when publishing via nginx (default `manage.playrservers.com`).
- `API_DOMAIN` – public hostname for the automation API when publishing via nginx (default `api.playrservers.com`).
- `APP_PORT` – internal management UI port (default `8000`).
- `APP_API_PORT` – internal API port (default `8001`).
- `APP_API_HOST` – bind address for the API service (defaults to `APP_HOST`).
- `INSTALL_NGINX` – set to `0` to skip nginx installation.

After installation the `manage-playrservers` systemd unit supervises both
services: the management UI listens on port `8000` and the public API listens on
port `8001`, binding to all interfaces by default. You can reach the UI directly
from your LAN using the server's IP address (for example,
`http://192.168.1.212:8000`). Expose `https://manage.playrservers.com` by
routing requests to the management port and map
`https://api.playrservers.com` to the API port. Ensure TLS certificates cover
both hostnames before exposing them to the internet.

Provision operator accounts from the server; self-registration is disabled:

```bash
sudo ./scripts/create_user.py "Alice Ops" alice@example.com
```

The script prompts for a password and prints the initial API key once (store it
securely; subsequent rotations occur from the web portal).

## Updating an existing deployment

Fetch the latest code, refresh Python dependencies, and restart the service without touching your SQLite data (so configured users and hypervisor connections remain intact):

```bash
sudo -u playrmanager git -C /opt/manage.playrservers pull --ff-only && sudo -u playrmanager /opt/manage.playrservers/.venv/bin/pip install -r /opt/manage.playrservers/requirements.txt && sudo systemctl restart manage-playrservers
```

## Configuration

The application stores its data in SQLite and exposes configuration through
environment variables:

| Environment Variable      | Description                                                   | Default                        |
| ------------------------- | ------------------------------------------------------------- | ------------------------------ |
| `MANAGEMENT_DB_PATH`      | Custom path to the SQLite database                            | `data/management.sqlite3`      |
| `MANAGEMENT_HOST`         | Bind address for the management UI                            | `0.0.0.0`                      |
| `MANAGEMENT_PORT`         | Listen port for the management UI                             | `8000`                         |
| `MANAGEMENT_API_HOST`     | Bind address for the API service                              | matches `MANAGEMENT_HOST`      |
| `MANAGEMENT_API_PORT`     | Listen port for the API service                               | `8001`                         |
| `MANAGEMENT_WORKERS`      | Number of uvicorn worker processes                            | `1`                            |
| `MANAGEMENT_RELOAD`       | Set to `true`/`1` to enable auto-reload (development only)    | `false`                        |
| `MANAGEMENT_PUBLIC_API_URL` | External URL advertised to agents via the portal             | `https://api.playrservers.com` |
| `MANAGEMENT_SESSION_SECRET` | Secret used to sign management sessions (must be set)        | generated by installer         |
| `MANAGEMENT_SESSION_SECURE`        | Enforce HTTPS-only session cookies (`false` for local dev)    | `true`                         |
| `MANAGEMENT_AGENT_USERNAME`        | SSH user that agents should provision on the hypervisor       | `hvdeploy`                     |
| `MANAGEMENT_AGENT_SSH_PORT`        | SSH port stored for auto-registered agents                    | `22`                           |
| `MANAGEMENT_AGENT_ALLOW_UNKNOWN_HOSTS` | Accept unknown host keys when connecting to new agents       | `false`                        |
| `MANAGEMENT_AGENT_KNOWN_HOSTS_PATH` | Known hosts file path applied to auto-registered agents       | unset                          |
| `MANAGEMENT_AGENT_CLOSE_OTHER_SESSIONS` | Whether agents should terminate other SSH sessions          | `true`                         |
| `MANAGEMENT_QEMU_IMAGE_ROOT`       | Base directory on the hypervisor for downloaded images, seeds, and unattended media (must already be writable by the SSH automation user) | `/var/lib/libvirt/images/playrservers` |


The systemd unit installed by `scripts/install.sh` sources `/etc/manage-playrservers.env`
(if present) so you can persist environment overrides there.

## Management interface

Navigate to `https://manage.playrservers.com` (or the hostname assigned by your
platform team) to access the operator portal. Accounts are created
with `scripts/create_user.py` and authenticate with an email + password. The UI
exposes three primary workflows:

- **Dashboard** – high-level overview of the deployment, including the API base
  URL that remote agents should target when connecting to the control plane.
- **Account &amp; API key** – update profile information, rotate credentials, and
  copy onboarding snippets for the remote agent.
- **Hypervisor management** – register virtualization hosts, inspect their
  virtual machines, dispatch lifecycle commands, and launch SSH sessions with
  the stored credentials. A deployment guide placeholder highlights where the
  remote agent documentation will live.

Session cookies are signed with `MANAGEMENT_SESSION_SECRET` and marked
`Secure`/`SameSite=Lax` so they are only transmitted over HTTPS.

## Guided VM deployments

With at least one hypervisor agent registered, the management dashboard can
bootstrap new guests end-to-end from the **Deploy a virtual machine** panel.
Select an operating system profile, adjust sizing, and the portal will download
the installer, prepare cloud-init or unattended media, and run `virt-install`
over SSH. The UI highlights the default credentials so operators can hand off
access immediately after provisioning.

### Supported profiles

- **Ubuntu Server 24.04 LTS** – streams the official cloud image from
  [ubuntu.com](https://ubuntu.com/download/server), seeds a `playradmin` account
  via cloud-init, and defaults to 4 GiB RAM, 2 vCPUs, and a 40 GiB disk.
- **Windows Server 2022 Datacenter (Evaluation)** – downloads the Microsoft
  evaluation ISO, generates an `Autounattend.xml`, and mounts it alongside the
  installer. A `playradmin` administrator account is created with the
  pre-configured password `PlayrServers!23`.

> **Note:** Windows automation requires an ISO authoring utility (`genisoimage`,
> `mkisofs`, or `xorrisofs`) to be present on the hypervisor so the unattended
> media can be generated. The evaluation ISO is subject to Microsoft's licensing
> terms and expires unless activated.

## Browser-based VM console

Each VM entry now includes a **Console** button that opens a streaming `virsh
console` session directly in the browser. Connections use the same stored SSH
credentials as other agent workflows and can be released with <kbd>Ctrl</kbd> +
<kbd>]</kbd>.

## API Overview

The automation endpoints live on the dedicated API service (default port `8001`).
When exposing `https://api.playrservers.com`, route that host to the API port so
public requests continue to use simple paths (e.g. `/health`, `/agents`). Every endpoint
except `/health` requires an API key presented in the `Authorization: Bearer <key>` header.

### Health

| Method | Path      | Description            |
| ------ | --------- | ---------------------- |
| GET    | `/health` | Service readiness ping |

### User & API key management

| Method | Path                     | Description                                    |
| ------ | ------------------------ | ---------------------------------------------- |
| GET    | `/users/me`              | Return the authenticated user's profile        |
| POST   | `/users/me/api-key/rotate` | Issue a new API key for the current user      |

User accounts are created by administrators via `scripts/create_user.py`; the
API does not expose a self-registration endpoint.

### Agent registry

| Method | Path                               | Description                                   |
| ------ | ---------------------------------- | --------------------------------------------- |
| GET    | `/agents`                          | List the caller's registered agents           |
| POST   | `/agents`                          | Register a new agent / virtualization host    |
| GET    | `/agents/{id}`                     | Retrieve metadata for a specific agent        |
| PATCH  | `/agents/{id}`                     | Update agent metadata or credentials          |
| DELETE | `/agents/{id}`                     | Remove an agent                               |

> **Security note:** SSH private keys uploaded to the control plane are stored
> encrypted at rest and are never retrievable via the public API. Legacy
> clients that previously called `/agents/{id}/credentials` now receive a
> `404 Not Found` response and should instead rely on key material supplied at
> registration time or the automatic provisioning flow documented below.

Agent registration payload example:

```bash
curl -X POST https://api.playrservers.com/agents \
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

### Agent auto-registration

Remote hosts running the [HVDeploy agent](https://github.com/PlayrTBH/HVDeploy)
call `POST /v1/servers/connect` to enrol themselves with the control plane. The
request must include an API key along with either a `hostname` or
`ip_address`—the server chooses sensible defaults for display names and SSH
connection details. On success the management API creates (or updates) the
hypervisor entry under **Hypervisors**, seeds it with the operator's automation
SSH private key, and returns the matching public key material for installation
on the host. Agents should consume this endpoint instead of attempting to fetch
private keys from the API—the credentials are automatically provisioned as part
of the registration handshake and never exposed in subsequent responses.

Each user profile receives a dedicated Ed25519 key pair at creation time. When
an agent connects the API loads the caller's private key, stores it alongside
the hypervisor record, and returns the matching public key so the host can trust
future automation sessions. Additional environment variables control the
provisioned SSH username, port, host verification policy, and whether the agent
should close existing SSH sessions after provisioning.

Example response payload:

```json
{
  "agent_id": 7,
  "name": "hv-01",
  "hostname": "192.0.2.10",
  "port": 22,
  "username": "hvdeploy",
  "authorized_keys": [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey playrservers@example.com"
  ],
  "close_other_sessions": true
}
```

Repeated calls from the same host update the stored hypervisor metadata rather
than creating duplicate entries, ensuring the portal always reflects the latest
SSH endpoint details.

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
- Ensure TLS termination protects API credentials in transit.
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
MANAGEMENT_RELOAD=true python main.py
```

Use `scripts/create_user.py` (or import `Database` in a REPL) to create a user
locally. The management UI is reachable at `http://127.0.0.1:8000` (or via your
machine's LAN IP) and the API on `http://127.0.0.1:8001`; target the API base
with the issued key to exercise the endpoints during development. When testing
over plain HTTP you can set `MANAGEMENT_SESSION_SECURE=false` to allow the
browser to retain the login session.
