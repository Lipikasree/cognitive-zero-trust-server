import asyncio
import json
import sys
from pathlib import Path

import pyotp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from czt.brain.engine import Engine, Session
from czt.brain.trust import Trust
from czt.store import Store
from czt.brain.totp import verify_and_consume


def test_totp_valid_code_is_accepted_once_and_cannot_be_replayed(tmp_path):
    now = 1_800_000_000
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).at(now)
    store = Store(str(tmp_path / "totp.sqlite3"))
    assert verify_and_consume("alice", code, {"alice": secret}, store, now)
    assert not verify_and_consume("alice", code, {"alice": secret}, store, now)
    store.close()


def test_engine_audit_stores_totp_outcome_but_never_secret_or_code(tmp_path, monkeypatch):
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    monkeypatch.setattr("czt.brain.engine.load_secrets", lambda: {"alice": secret})
    store = Store(str(tmp_path / "audit.sqlite3"))

    class Writer:
        def write(self, event): pass

    class Output:
        def write(self, data): pass
        async def drain(self): pass

    class Input:
        async def readline(self): return (code + "\n").encode()

    class Process:
        stdout = Output(); stdin = Input()
        def get_extra_info(self, name): return ("127.0.0.1", 1234)

    settings = json.loads((Path(__file__).resolve().parents[1] / "config/settings.json").read_text(encoding="utf-8"))
    prior = tmp_path / "empty.jsonl"
    prior.write_text("", encoding="utf-8")
    engine = Engine(store, Writer(), settings, prior_path=prior)
    engine.attacker_profile.counts.clear()
    session = Session(engine, "totp-audit", "alice")
    session.profile = type("Profile", (), {"surprise_evidence": lambda *args: 0.0})()
    decision, _ = asyncio.run(session.evaluate("rm /tmp/nonexistent-audit-probe", Process()))
    payloads = "".join(row[0] for row in store.db.execute("SELECT payload FROM events WHERE session_id='totp-audit'"))
    command = store.db.execute("SELECT raw FROM session_commands WHERE session_id='totp-audit'").fetchone()[0]
    assert decision == "allow"
    assert '"method": "totp"' in payloads and '"outcome": "confirmed"' in payloads
    assert secret not in payloads and code not in payloads and code not in command
    store.close()


def test_totp_wrong_expired_malformed_and_unenrolled_codes_fail(tmp_path):
    now = 1_800_000_000
    secret = pyotp.random_base32()
    store = Store(str(tmp_path / "totp.sqlite3"))
    assert not verify_and_consume("alice", "000000", {"alice": secret}, store, now)
    expired = pyotp.TOTP(secret).at(now - 90)
    assert not verify_and_consume("alice", expired, {"alice": secret}, store, now)
    assert not verify_and_consume("alice", "12x456", {"alice": secret}, store, now)
    assert not verify_and_consume("alice", "123456", {}, store, now)
    store.close()


def test_engine_stops_after_three_failed_totp_attempts_without_auditing_codes(tmp_path, monkeypatch):
    secret = pyotp.random_base32()
    monkeypatch.setattr("czt.brain.engine.load_secrets", lambda: {"alice": secret})
    store = Store(str(tmp_path / "totp.sqlite3"))

    class Writer:
        def __init__(self): self.rows = []
        def write(self, event): self.rows.append(event)

    class Output:
        def write(self, data): pass
        async def drain(self): pass

    class Input:
        def __init__(self): self.calls = 0
        async def readline(self):
            self.calls += 1
            return b"000000\n"

    class Process:
        stdout = Output()
        def __init__(self): self.stdin = Input()
        def get_extra_info(self, name): return ("127.0.0.1", 1234)

    settings = json.loads((Path(__file__).resolve().parents[1] / "config/settings.json").read_text(encoding="utf-8"))
    settings["totp_attempt_limit"] = 3
    writer = Writer()
    prior = tmp_path / "empty.jsonl"
    prior.write_text("", encoding="utf-8")
    engine = Engine(store, writer, settings, prior_path=prior)
    engine.attacker_profile.counts.clear()
    process = Process()
    session = Session(engine, "totp-fail", "alice")
    session.profile = type("Profile", (), {"surprise_evidence": lambda *args: 0.0})()
    decision, _ = asyncio.run(session.evaluate("rm /tmp/demo-file", process))
    saved = json.dumps(writer.rows) + json.dumps([r[0] for r in store.db.execute("SELECT payload FROM events")])
    assert process.stdin.calls == 3
    assert decision == "block"
    assert any(event.get("method") == "totp" and event.get("outcome") == "failed" for event in writer.rows)
    assert "000000" not in saved
    store.close()


def test_lower_cost_uncertainty_challenge_keeps_inline_confirmation(tmp_path):
    store = Store(str(tmp_path / "inline.sqlite3"))

    class Writer:
        def __init__(self): self.rows = []
        def write(self, event): self.rows.append(event)

    class Output:
        def write(self, data): pass
        async def drain(self): pass

    class Input:
        async def readline(self): return b"YES\n"

    class Process:
        stdout = Output(); stdin = Input()
        def get_extra_info(self, name): return ("127.0.0.1", 1234)

    settings = json.loads((Path(__file__).resolve().parents[1] / "config/settings.json").read_text(encoding="utf-8"))
    writer = Writer()
    prior = tmp_path / "empty.jsonl"
    prior.write_text("", encoding="utf-8")
    engine = Engine(store, writer, settings, prior_path=prior)
    engine.attacker_profile.counts.clear()
    session = Session(engine, "inline", "alice", "developer")
    session.trust = Trust(.5)
    session.profile = type("Profile", (), {"surprise_evidence": lambda *args: 0.0})()
    decision, _ = asyncio.run(session.evaluate("systemctl status ssh", Process()))
    assert decision == "allow"
    assert any(event.get("method") == "inline_confirmation" and event.get("outcome") == "confirmed" for event in writer.rows)
    store.close()
