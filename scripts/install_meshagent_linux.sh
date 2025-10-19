#!/usr/bin/env bash
# Automated MeshAgent enrollment for Linux endpoints.
# Usage: customize MESH_SERVER and MESH_GROUP_ID, then run as root.

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

