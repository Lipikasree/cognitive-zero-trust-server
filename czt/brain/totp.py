"""TOTP verification with durable replay prevention."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pyotp


def load_secrets(path: str | Path | None = None) -> dict[str, str]:
    path = Path(path or os.environ.get("CZTS_TOTP_SECRETS", "keys/totp_secrets.json"))
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in data.items()):
        raise ValueError("TOTP secret file must be a JSON object of usernames to secrets")
    return data


def verify_and_consume(username: str, code: str, secrets: dict[str, str], store, now: float | None = None) -> bool:
    """Verify a current six-digit code and atomically prevent time-step reuse."""
    secret = secrets.get(username)
    if not secret or not re.fullmatch(r"\d{6}", code.strip()):
        return False
    now = time.time() if now is None else float(now)
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    if not totp.verify(code.strip(), for_time=now, valid_window=0):
        return False
    step = int(now // totp.interval)
    return bool(store.consume_totp_step(username, step))
