# MeshCentral Remote Management Architecture

## Overview
This document describes how to stand up a MeshCentral server that provides full remote management of Linux endpoints today and keeps the door open for adding Windows endpoints later. The goal is to run a centrally managed MeshCentral service that communicates with lightweight MeshAgent services installed on every managed system.


## Components
- **MeshCentral server** – A Node.js application that exposes the management portal, handles device group policies, stores audit logs, and distributes MeshAgent binaries.
- **Database storage** – MeshCentral supports NeDB (default), MongoDB, and PostgreSQL. MongoDB is recommended for production scale.
- **Reverse proxy / TLS terminator** – Optional but recommended. Use Nginx, Caddy, or Traefik to provide HTTPS, WebSocket upgrades, and certificate automation (Let’s Encrypt).
- **MeshAgent** – The endpoint agent that keeps a persistent TLS-encrypted tunnel to the MeshCentral server. It exposes remote terminal, file transfer, and remote desktop capabilities on supported platforms.

## Network requirements
- Allow inbound TCP 443 (or your chosen port) on the MeshCentral server.
- Ensure outbound TCP connectivity from agents to the server on the same port.
- If using self-hosted certificates, distribute the CA certificate to agents so they trust the server.

## Authentication and authorization
- Create administrator accounts with 2FA for MeshCentral.
- Organize devices into "device groups" (aka meshes) and assign granular permissions to roles (full, remote desktop only, terminal-only, etc.).
- Enable audit log retention and syslog forwarding for compliance requirements.

## Backup strategy
- Back up the MeshCentral `meshcentral-data` directory and the MongoDB database regularly.
- Store configuration files, TLS keys, and database dumps in encrypted off-site storage.
- Test restores by spinning up a staging server regularly.

## Server deployment

### 1. Provision infrastructure
- Deploy an Ubuntu Server 22.04 LTS VM (2 vCPU, 4 GB RAM, 40 GB disk) behind a static public IP.
- Harden the host: enable automatic security updates, configure UFW to allow only SSH (22/tcp) and HTTPS (443/tcp).

### 2. Install dependencies
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs build-essential
yarn global add pm2@latest
```

### 3. Install MeshCentral
```bash
sudo npm install meshcentral -g
sudo useradd --system --home-dir /opt/meshcentral --shell /usr/sbin/nologin meshcentral
sudo mkdir -p /opt/meshcentral
sudo chown meshcentral:meshcentral /opt/meshcentral
sudo -u meshcentral meshcentral
```
The first launch creates `/opt/meshcentral/meshcentral-data` with a default `config.json`.

### 4. Configure the service
Create `/etc/systemd/system/meshcentral.service`:
```ini
[Unit]
Description=MeshCentral Server
After=network.target

[Service]
Type=simple
User=meshcentral
WorkingDirectory=/opt/meshcentral
ExecStart=/usr/bin/node /usr/lib/node_modules/meshcentral
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```
Then run:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now meshcentral
```

### 5. Configure TLS and domains
Edit `/opt/meshcentral/meshcentral-data/config.json` to enable HTTPS, Let’s Encrypt, and MongoDB:
```json
{
  "$schema": "https://meshcentral.com/schemas/config.json",
  "settings": {
    "Port": 443,
    "AliasPort": 443,
    "RedirPort": 80,
    "TlsOffload": false,
    "cert": {
      "letsencrypt": {
        "email": "admin@example.com",
        "names": "mesh.example.com"
      }
    },
    "mongodb": "mongodb://meshcentral:REPLACE_PASSWORD@db01.internal:27017/meshcentral"
  },
  "domains": {
    "": {
      "Title": "MeshCentral",
      "Title2": "Remote Management",
      "NewAccounts": true,
      "certurl": "https://mesh.example.com",
      "AgentConfig": {
        "UpdateCheck": true,
        "AutoConnect": true
      }
    }
  }
}
```
Restart the service after edits: `sudo systemctl restart meshcentral`.

## Linux agent deployment

### Interactive install via web UI
1. Log in as an administrator and create a device group.
2. Click **Add Agent** → **Linux** and download the `meshagent` installer.
3. Run the downloaded script on the target system with root privileges.

### Automated systemd deployment
Use the helper script below to enroll Linux nodes unattended:

`scripts/install_meshagent_linux.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

MESH_SERVER="https://mesh.example.com"
MESH_GROUP_ID="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

if [[ -z "${MESH_SERVER}" || -z "${MESH_GROUP_ID}" ]]; then
  echo "Please set MESH_SERVER and MESH_GROUP_ID before running." >&2
  exit 1
fi

WORKDIR="/opt/meshagent"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

curl -fsSLo meshagent "$MESH_SERVER/meshagents?id=$MESH_GROUP_ID&script=1"
chmod +x meshagent

./meshagent -install

systemctl enable --now meshagent
```

The script downloads the correct agent binary for the host architecture, installs it as a service, and ensures it starts at boot.

### Hardening tips
- Limit which administrators can request remote terminals or file access using device-group permissions.
- Enable alerting on agent disconnects and critical events in the MeshCentral portal.
- Rotate the `MeshCentral/certificates/` directory when rotating TLS certificates.

## Windows roadmap considerations
- Generate a Windows agent installer (`meshagent64.exe`) from the same device group; the MeshCentral server provides MSI packaging.
- Use Group Policy or Microsoft Intune to deploy the MSI silently when ready.
- Document Windows-specific privileges and driver requirements before rolling out.

## Monitoring and maintenance
- Use `pm2` or systemd to supervise the Node.js process and auto-restart on crash.
- Aggregate MeshCentral logs to a SIEM via syslog or filebeat.
- Patch MeshCentral regularly: `sudo npm install meshcentral@latest -g` followed by `systemctl restart meshcentral`.
- Watch https://github.com/Ylianst/MeshCentral/releases for security updates.

