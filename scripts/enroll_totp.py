"""Enroll a demo user in TOTP; generated secret and QR are sensitive files."""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

import pyotp
import qrcode

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "keys"
SECRETS = KEYS / "totp_secrets.json"


def lock_down(path: Path) -> None:
    if os.name == "nt":
        identity = subprocess.check_output(["whoami"], text=True).strip()
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(F)", "SYSTEM:(F)"], check=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--replace", action="store_true", help="replace an existing TOTP enrollment")
    args = parser.parse_args()
    configured = json.loads((ROOT / "config/users.json").read_text(encoding="utf-8"))
    usernames = {user["username"] for user in configured["users"] if user.get("enabled", True)}
    if args.username not in usernames:
        parser.error("username must match an enabled account in config/users.json")
    KEYS.mkdir(exist_ok=True)
    data = json.loads(SECRETS.read_text(encoding="utf-8")) if SECRETS.exists() else {}
    if args.username in data and not args.replace:
        parser.error("user is already enrolled; use --replace only during a deliberate reset")
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=args.username, issuer_name="Cognitive Zero Trust Server")
    qr_path = KEYS / f"totp_{re.sub(r'[^A-Za-z0-9_.-]', '_', args.username)}.png"
    qrcode.make(uri).save(qr_path)
    data[args.username] = secret
    temp = SECRETS.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lock_down(temp)
    os.replace(temp, SECRETS)
    lock_down(SECRETS)
    print(f"Enrollment created for {args.username}. Scan {qr_path} with an authenticator app.")
    print("Delete the QR image after scanning. Secret and QR are private credentials; do not share or log them.")


if __name__ == "__main__":
    main()
