"""Create real, blocked gateway sessions to exercise restricted/discard alerts."""
import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

import asyncssh
import pyotp
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from czt.store import Store

load_dotenv(ROOT / ".env")
DB = ROOT / "data" / "czts.sqlite3"
EVENTS = ROOT / "data" / "events.jsonl"
OUT = ROOT / "eval" / "results"


async def read_until(reader, needle: bytes, timeout: float = 20) -> bytes:
    collected = bytearray()
    async with asyncio.timeout(timeout):
        while needle not in collected:
            chunk = await reader.read(1)
            if not chunk:
                break
            collected.extend(chunk)
    return bytes(collected)


async def run_case(index: int, expected_state: str, bad_code: str) -> dict:
    # Unlock only the demo account between discard cases so each trial starts
    # independently and reaches the gateway's actual evaluator.
    store = Store(str(DB))
    store.unlock("alice")
    store.close()
    async with asyncssh.connect(
        "127.0.0.1", port=2222, username="alice",
        client_keys=[str(ROOT / "keys" / "alice_client")],
        known_hosts=None, login_timeout=90,
    ) as connection:
        process = await connection.create_process(
            term_type="xterm-256color", term_size=(80, 24), encoding=None
        )
        await asyncio.wait_for(process.stdout.read(4096), timeout=45)
        with sqlite3.connect(DB) as db:
            live = db.execute(
                "SELECT id FROM sessions WHERE username='alice' AND end IS NULL ORDER BY start DESC LIMIT 1"
            ).fetchone()
        if not live:
            raise RuntimeError("gateway did not persist a live test session")
        session_id = live[0]
        process.stdin.write(b"cat /etc/shadow\r")
        await process.stdin.drain()
        first_prompt = await read_until(process.stdout, b"TOTP required", timeout=20)
        if b"TOTP required" not in first_prompt:
            raise RuntimeError("expected TOTP step-up did not occur")
        for attempt in range(3):
            process.stdin.write(bad_code.encode("ascii") + b"\r")
            await process.stdin.drain()
            if attempt < 2:
                await read_until(process.stdout, b"TOTP required", timeout=8)
        blocked = await read_until(process.stdout, b"[CZTS BLOCK]", timeout=15)
        if b"[CZTS BLOCK]" not in blocked:
            raise RuntimeError("gateway did not block the failed TOTP command")

        if expected_state == "discarded":
            # Repeat a sensitive-file read which the restricted policy blocks.
            # This drives belief below the discard threshold without executing
            # a network, shell, or destructive command on the target.
            blocked_probe = b"cat /etc/shadow\r"
            for attempt in range(2):
                process.stdin.write(blocked_probe)
                await process.stdin.drain()
                marker = b"[CZTS DISCARD]" if attempt == 1 else b"[CZTS BLOCK]"
                result = await read_until(process.stdout, marker, timeout=15)
                if marker not in result:
                    raise RuntimeError(f"expected blocked risk probe {attempt + 1} was not recorded")
            process.close()
            await process.wait_closed()
        else:
            process.stdin.write(b"exit\r")
            await process.stdin.drain()
            process.close()
            await process.wait_closed()

        # Allow the session-finalization transaction to commit before checking.
        await asyncio.sleep(0.25)
        with sqlite3.connect(DB) as db:
            final_state = db.execute(
                "SELECT final_state FROM sessions WHERE id=?", (session_id,)
            ).fetchone()[0]
        if final_state != expected_state:
            raise RuntimeError(f"expected {expected_state}; gateway recorded {final_state}")
        return {
            "trial": index,
            "session_id": session_id,
            "expected_final_state": expected_state,
            "gateway_final_state": final_state,
            "totp_attempts": 3,
            "test_commands_forwarded": False,
        }


async def main(count: int) -> None:
    secret = json.loads((ROOT / "keys" / "totp_secrets.json").read_text(encoding="utf-8"))["alice"]
    results = []
    for state in ("restricted", "discarded"):
        for index in range(1, count + 1):
            current = int(pyotp.TOTP(secret).now())
            bad_code = f"{(current + 1) % 1_000_000:06d}"
            results.append(await run_case(index, state, bad_code))
            print(json.dumps({"state": state, "trial": index, "session_id": results[-1]["session_id"], "gateway_final_state": state}), flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "live_alert_sessions_raw.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    summary = {
        "method": "real interactive SSH sessions through the gateway; wrong TOTP and repeated sensitive-file reads are blocked; no risky commands are forwarded",
        "trials_per_state": count,
        "session_count": len(results),
        "restricted_sessions": sum(x["gateway_final_state"] == "restricted" for x in results),
        "discarded_sessions": sum(x["gateway_final_state"] == "discarded" for x in results),
        "gateway_policy_path": True,
        "email_receipt_timing": "measured separately; local webhook timestamps do not prove inbox arrival time",
    }
    (OUT / "live_alert_sessions_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=5, choices=range(5, 11), metavar="5..10")
    args = parser.parse_args()
    asyncio.run(main(args.count))
