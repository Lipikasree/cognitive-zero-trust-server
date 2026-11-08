# Windows quick start

This starts the SSH gateway, private Ubuntu target, Loki, Promtail, and Grafana. Use Windows PowerShell from the project root.

## Requirements

- Windows 10 or 11 with Docker Desktop running in Linux-container mode.
- Python 3.11 or newer, with the Python launcher `py` available.
- OpenSSH client (`ssh.exe`).

## Install and configure

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r eval/requirements.txt
Copy-Item .env.example .env
```

Set a private Grafana password in `.env`. This PowerShell example generates a random value without printing it:

```powershell
$grafanaPassword = python -c "import secrets; print(secrets.token_urlsafe(32))"
(Get-Content .env) -replace '^GRAFANA_ADMIN_PASSWORD=.*$', "GRAFANA_ADMIN_PASSWORD=$grafanaPassword" | Set-Content .env
```

Email is optional for the local demo. The example configuration leaves SMTP disabled. To enable it, create a fresh SMTP key in Brevo, set `GF_SMTP_ENABLED=true`, and fill `GF_SMTP_HOST`, `GF_SMTP_USER`, `GF_SMTP_PASSWORD`, `GF_SMTP_FROM_ADDRESS`, and `GF_ALERT_RECIPIENT` in the ignored `.env` file. Never paste the key into source files or screenshots.

## Create keys and enroll TOTP

```powershell
python scripts/generate_keys.py
python scripts/enroll_totp.py alice
```

Scan `keys/totp_alice.png` with an authenticator app. After scanning, delete the QR image:

```powershell
Remove-Item -LiteralPath .\keys\totp_alice.png
```

The keys and TOTP seed remain under the ignored `keys/` folder. Do not add that folder's contents to source control.

## Start the services

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
docker compose --env-file .env -f deploy/docker-compose.yml ps
```

The gateway is available at `127.0.0.1:2222`. Grafana and Loki are bound to loopback at ports 3000 and 3100. The Ubuntu target is on an internal Docker network and has no host-published SSH port.

## Try SSH and the demo

In a second PowerShell window from the project root:

```powershell
ssh -p 2222 -i .\keys\alice_client alice@127.0.0.1 "whoami"
ssh -tt -p 2222 -i .\keys\alice_client alice@127.0.0.1
.\scripts\demo.ps1
```

The first command exercises exec mode. Interactive PTY capture is a prototype. The demo script runs a normal command and checks that a sensitive command is blocked.

High-cost commands can prompt for the current six-digit TOTP code. Three failed attempts block the command. Never include a code in a bug report or audit log.

## Review sessions and control

```powershell
python -m czt.admin.cli sessions
python -m czt.admin.cli show <session-id>
python -m czt.admin.cli label <session-id> false_positive
python -m czt.admin.cli label <session-id> confirmed_attack
python -m czt.admin.cli promote
python -m czt.admin.cli restrict <session-id>
python -m czt.admin.cli terminate <session-id>
python -m czt.admin.cli clear-control <session-id>
python -m czt.admin.cli unlock alice
python -m czt.admin.cli reset-auth alice
```

The gateway checks mature quarantined sessions every ten seconds. Promotion eligibility and the label effects are described in [Limits and behavior](limitations.md).

## Open Grafana and stop

Open [http://localhost:3000](http://localhost:3000) and sign in as `admin` with the password from `.env`. The provisioned dashboard and alerts are in the CZTS folder. Local alert summaries are written to `data/alerts.jsonl`.

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml down
```

For backups, key rotation, monitoring, and firewall guidance, see [operations](operations.md) and [key management](key-management.md).
