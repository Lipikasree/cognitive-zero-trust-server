# Operations runbook

These are manual MVP procedures. Automated backup, key rotation, and recovery
are not implemented. Keep backups encrypted and access-controlled.

## Backup and recovery

Persistent host data is in `data/` (SQLite audit DB, JSONL event and alert
logs, and learned state), `keys/` (SSH and TOTP secrets), and the ignored raw
dataset folders. Grafana's provisioning files live under
`deploy/grafana/provisioning/`; its runtime database currently lives in the
Grafana container because Compose does not mount a persistent Grafana volume.

To make a local backup, stop the gateway before copying SQLite and stop Grafana
before copying its runtime database. Protect the destination like a credential
store:

```powershell
$backup = Join-Path $env:LOCALAPPDATA "CZTS-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $backup, "$backup\data", "$backup\keys", "$backup\grafana" -Force
docker compose --env-file .env -f deploy/docker-compose.yml stop gateway grafana
Copy-Item data\czts.sqlite3, data\events.jsonl, data\alerts.jsonl -Destination "$backup\data" -ErrorAction SilentlyContinue
Copy-Item keys\* -Destination "$backup\keys" -Force
$grafana = docker compose --env-file .env -f deploy/docker-compose.yml ps -aq grafana
docker cp "${grafana}:/var/lib/grafana/." "$backup\grafana"
docker compose --env-file .env -f deploy/docker-compose.yml start gateway grafana
```

For recovery, stop the stack, restore the protected `data` and `keys` copies to
the project paths, then copy the saved Grafana contents back before starting
Compose:

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml stop
Copy-Item "$backup\data\*" data -Force
Copy-Item "$backup\keys\*" keys -Force
$grafana = docker compose --env-file .env -f deploy/docker-compose.yml ps -aq grafana
docker cp "$backup\grafana\." "${grafana}:/var/lib/grafana"
docker compose --env-file .env -f deploy/docker-compose.yml up -d
```

Verify dashboard provisioning, gateway SSH, the target host-key pin, and recent
audit events. Do not overwrite newer data until the recovery point is selected
deliberately.

## Key and TOTP rotation

SSH rotation steps are documented in [key-management.md](key-management.md).
The procedure is manual: stage and verify replacement keys before removing
old trust, then recreate the affected containers.

To enroll or reset TOTP for a user, run `python scripts/enroll_totp.py alice`
or, for a deliberate re-enrollment, add `--replace`. Scan the generated
`keys/totp_<user>.png` QR with the user's authenticator, then securely delete
the QR image. Keep `keys/totp_secrets.json` access-controlled and out of logs,
screenshots, issue reports, and source control. Recreate the gateway after
enrollment so the read-only secret mount is refreshed. A TOTP code is current
for one 30-second time step and can succeed only once; three failed entries
block that command. No code is included in audit data.

## Monitoring and gateway health

Open Grafana at `http://localhost:3000`. Review the provisioned CZTS dashboard,
the restricted-session and discarded-session alerts, and `data/alerts.jsonl`
for local delivery receipts. If SSH stops responding, check:

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml ps
docker logs --tail 100 czts-gateway
Test-NetConnection 127.0.0.1 -Port 2222
```

The gateway may take extra time on startup while it loads the temporal Cowrie
training profile. If it remains unavailable, inspect the gateway log for
profile or key-file errors. Grafana and alert-sink logs can be inspected with
`docker compose logs --tail 100 grafana alert-sink`.

## Email alerts through Brevo

The SMTP server, port, and login are read from `.env`; the password/key stays
there and is passed to Grafana as an environment variable. SMTP STARTTLS
authentication can be checked without sending a message using:

```powershell
python -c "import os,smtplib,ssl; from dotenv import load_dotenv; load_dotenv('.env'); host,port=os.environ['GF_SMTP_HOST'].rsplit(':',1); s=smtplib.SMTP(host,int(port),timeout=15); s.ehlo(); s.starttls(context=ssl.create_default_context()); s.ehlo(); s.login(os.environ['GF_SMTP_USER'],os.environ['GF_SMTP_PASSWORD']); s.quit(); print('SMTP authentication passed')"
```

Set `GF_SMTP_FROM_ADDRESS` to a sender verified in Brevo and
`GF_ALERT_RECIPIENT` to the destination inbox, then recreate Grafana. The
provisioned contact point fans out to local capture and email for the
restricted/discarded rules. Use Grafana's contact point Test action and check
the recipient inbox and spam folder. Brevo delivery statistics can help
diagnose missing messages. Five restricted and five discarded sessions have
been run through the live gateway. The local webhook recorded the resulting
state alerts with median and worst gateway-event-to-webhook delays in
`eval/results/alert_latency_summary.json`. This is not event-to-inbox latency.
The user confirmed the live alert emails arrived in Gmail around 7:12–7:16 pm
IST. This approximate range overlaps the batch but begins before its first
gateway event, so it does not support per-alert inbox-delay statistics. For a
future measurement, record each matching message's Gmail received timestamp and
pair it to its session ID/event timestamp. Authentication or a Grafana test
notification alone does not confirm live incident-email delivery. Do not put
the SMTP key in provisioning files, screenshots, or logs.

## Windows host firewall and exposed ports

By default SSH is published only on `127.0.0.1:2222`, so remote hosts cannot
reach it. Grafana (`127.0.0.1:3000`) and Loki (`127.0.0.1:3100`) are also
loopback-only. The Ubuntu target's SSH port 22 is **not** published on the
Windows host; it is reachable only from the gateway on the private Docker
backend network.

If an operator deliberately changes the gateway bind address to expose SSH,
add a Windows Firewall allow rule limited to trusted source addresses, for
example from an elevated PowerShell prompt:

```powershell
New-NetFirewallRule -DisplayName "CZTS SSH from trusted subnet" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 2222 -RemoteAddress 192.0.2.0/24
```

Replace the documentation subnet with the actual trusted client range, verify
Docker Desktop's port-publishing behavior on that host, and test from both an
allowed and a denied source. Do not publish the target port.
