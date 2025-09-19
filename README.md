# QEMU Management Service

A secure FastAPI-based web service that manages QEMU/KVM virtual machines on
remote hosts over SSH using private-key authentication only. The service is
intended for deployment on a controlled network where operators can trigger VM
lifecycle actions and inspect their state through an authenticated API.

## Features

- 🔐 **Token-protected API** – all management endpoints require a pre-shared
  bearer token, preventing unauthenticated access.
- 🔑 **Private key authentication** – SSH connections are established with
  explicit private keys; passwords and SSH agents are disabled.
- 📦 **QEMU/virsh integration** – list domains and perform lifecycle operations
  (`start`, `shutdown`, `destroy`, `reboot`, `dominfo`).
- 🛡️ **Strict host verification** – reject unknown host keys by default with
  optional per-host overrides.
- 📁 **Configurable hosts** – manage multiple virtualization servers defined via
  a YAML configuration file.
- 🧾 **Structured responses** – command responses include the executed command,
  exit status, and stdout/stderr for auditing.

## Requirements

- Python 3.10+
- Access to remote hosts running libvirt/`virsh`
- SSH private keys readable by the service process

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Hosts are defined in a YAML file. Copy `config/hosts.example.yaml` to a secure
location, edit the values, and point the service to it via the
`MANAGEMENT_CONFIG_PATH` environment variable. Each host entry requires:

- `name` – unique identifier used in API paths
- `hostname` – IP or DNS name of the hypervisor
- `port` – SSH port (defaults to 22)
- `username` – user on the remote system
- `private_key_path` – path to the private key used for authentication
- `allow_unknown_hosts` – (optional) set to `true` to trust unknown host keys
- `known_hosts_file` – (optional) custom known hosts file

Example:

```yaml
hosts:
  - name: "production"
    hostname: "qemu1.internal"
    port: 22
    username: "qemu-admin"
    private_key_path: "/srv/keys/qemu_admin_ed25519"
    allow_unknown_hosts: false
    known_hosts_file: "/etc/ssh/ssh_known_hosts"
```

The file `config/hosts.yaml` is provided with placeholder data so the
application can start. Replace it with your own configuration or override the
path using `MANAGEMENT_CONFIG_PATH`.

### API Tokens

Set the `MANAGEMENT_API_TOKENS` environment variable to a comma-separated list
of bearer tokens before launching the server. Example:

```bash
export MANAGEMENT_API_TOKENS="token1,token2,another-secret"
```

Requests must supply one of these values via the `Authorization` header:
`Authorization: Bearer <token>`.

## Running the Service

Launch the service with Uvicorn. The server binds to port 80 as required:

```bash
python main.py
```

Running on port 80 typically requires elevated privileges or port redirection
(e.g., using `setcap`, a reverse proxy, or `authbind`).

### Systemd snippet

```ini
[Service]
Environment=MANAGEMENT_API_TOKENS=prod-super-secret
Environment=MANAGEMENT_CONFIG_PATH=/etc/qemu-manager/hosts.yaml
ExecStart=/usr/bin/python /opt/qemu-management/main.py
User=qemu-manager
Group=qemu-manager
```

## API Overview

All endpoints (except `/health`) require authentication.

| Method | Path                                             | Description                    |
| ------ | ------------------------------------------------ | ------------------------------ |
| GET    | `/health`                                        | Service health probe           |
| GET    | `/hosts`                                         | List configured hosts          |
| GET    | `/hosts/{host}/vms`                              | List VMs on the host           |
| GET    | `/hosts/{host}/vms/{vm}`                         | Retrieve `virsh dominfo` data  |
| POST   | `/hosts/{host}/vms/{vm}/start`                   | Start a VM                     |
| POST   | `/hosts/{host}/vms/{vm}/shutdown`                | Gracefully shut down a VM      |
| POST   | `/hosts/{host}/vms/{vm}/force-stop`              | Force stop a VM (`virsh destroy`) |
| POST   | `/hosts/{host}/vms/{vm}/reboot`                  | Reboot a VM                    |

## Security Recommendations

- Store configuration and private keys outside the project directory with
  restricted file permissions.
- Use distinct API tokens per operator and rotate them regularly.
- Deploy behind a TLS-terminating reverse proxy (e.g., nginx) to encrypt
  traffic, since the service itself listens on HTTP/80.
- Limit network access to the service to trusted clients only.
- Monitor logs from remote hosts for suspicious activity.

## Development

To run the application in development mode with live reload, you can use
Uvicorn directly:

```bash
MANAGEMENT_API_TOKENS=dev-secret uvicorn app.api:app --host 0.0.0.0 --port 80 --reload
```

Be sure to provide a valid configuration file and accessible SSH keys when
interacting with real hosts.
