"""Convert Cowrie JSON event logs into session-separated command records.

Only cowrie.command.input events without a ``realm`` are treated as shell
commands. Other events (notably login events containing passwords) are ignored.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, TextIO
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from czt.brain.tokenizer import redact


def _open_text(path: Path) -> TextIO:
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix.lower() == ".gz" else path.open("r", encoding="utf-8", errors="replace")


def convert(paths: Iterable[Path], output: Path, seed: int = 73, train_fraction: float = 0.6, validation_fraction: float = 0.2) -> list[dict]:
    if train_fraction <= 0 or validation_fraction <= 0 or train_fraction + validation_fraction >= 1:
        raise ValueError("train and validation fractions must be positive and sum to less than 1")
    sessions: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path in sorted(map(Path, paths)):
        with _open_text(path) as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
                if event.get("eventid") != "cowrie.command.input" or event.get("realm"):
                    continue
                session_id = event.get("session")
                command = event.get("input")
                if isinstance(session_id, str) and session_id and isinstance(command, str) and command.strip():
                    sensor = str(event.get("sensor", ""))
                    group_id = f"{sensor}:{session_id}" if sensor else session_id
                    sessions[group_id].append((str(event.get("timestamp", event.get("ts", ""))), redact(command.strip())))

    ids = sorted(sessions)
    random.Random(seed).shuffle(ids)
    train_cut = int(len(ids) * train_fraction)
    validation_cut = int(len(ids) * (train_fraction + validation_fraction))
    rows = []
    for index, session_id in enumerate(ids):
        split = "train" if index < train_cut else "validation" if index < validation_cut else "test"
        ordered = sorted(sessions[session_id], key=lambda item: item[0])
        rows.append({"session_id": "cowrie-" + hashlib.sha256(session_id.encode()).hexdigest()[:20], "username": "cowrie_attacker", "role": "attacker", "label": "attack", "split": split, "source": "cowrie_jsonl", "seed": seed, "commands": [command for _, command in ordered]})
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path, help="Cowrie cowrie.json files (one JSON object per line)")
    parser.add_argument("--output", type=Path, default=Path("data/cowrie_sessions.jsonl"))
    parser.add_argument("--seed", type=int, default=73)
    args = parser.parse_args()
    rows = convert(args.logs, args.output, seed=args.seed)
    print(f"Wrote {len(rows)} sessions to {args.output}")


if __name__ == "__main__":
    main()
