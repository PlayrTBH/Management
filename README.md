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
- ✅ **Command-line bootstrap** – `scripts/create_user.py` initialises the
  database (if needed) and adds user records for local testing.
- ⚠️ **No runtime services** – there is no HTTP API, management UI, or hypervisor
  automation at this stage. Running `python main.py` simply prepares the
  database and prints a reminder about the removed components.

## Getting started

Create a virtual environment and install requirements (none are currently
mandated, but the command keeps your environment tidy):

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

The helper script prompts for a password (minimum 12 characters) and confirms
that only basic login data is stored.

## Development

Pytest drives the remaining unit tests:

```bash
pytest
```

The goal for this phase is simply to provide a trustworthy persistence layer
while the new management and API experiences are designed. Feel free to iterate
on the database schema and supporting utilities before larger application
components return.
