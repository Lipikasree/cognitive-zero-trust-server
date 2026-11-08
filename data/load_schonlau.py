"""Convert the Schonlau masquerade files into session-level JSONL records.

The source is not bundled. See data/EXTERNAL_DATA.md for licensing and format
notes. A filename-to-user ordering is required for the 100 x 50 truth matrix.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Iterable


def _read_commands(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _read_locations(path: Path) -> list[list[int]]:
    rows: list[list[int]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "%")):
            continue
        cells = line.replace(",", " ").split()
        try:
            row = [int(cell) for cell in cells]
        except ValueError:
            # Permit one textual header, but reject malformed data rows.
            if not rows:
                continue
            raise ValueError(f"invalid contamination value on line {line_number}")
        if any(value not in (0, 1) for value in row):
            raise ValueError(f"contamination values must be 0 or 1 (line {line_number})")
        rows.append(row)
    if len(rows) != 100 or any(len(row) != 50 for row in rows):
        raise ValueError(f"expected a 100 by 50 contamination matrix, got {len(rows)} rows")
    return rows


def _filename_order(path: Path):
    match = re.fullmatch(r"User(\d+)", path.name, flags=re.IGNORECASE)
    return (0, int(match.group(1))) if match else (1, path.name.casefold())


def convert(command_files: Iterable[Path], locations_file: Path, output: Path) -> list[dict]:
    files = sorted((Path(p) for p in command_files if Path(p).is_file() and re.fullmatch(r"User\d+", Path(p).name, flags=re.IGNORECASE)), key=_filename_order)
    if len(files) != 50:
        raise ValueError(f"expected exactly 50 command files, got {len(files)}")
    matrix = _read_locations(Path(locations_file))
    rows: list[dict] = []
    for user_index, path in enumerate(files):
        commands = _read_commands(path)
        if len(commands) != 15000:
            raise ValueError(f"{path.name}: expected 15000 command lines, got {len(commands)}")
        user = path.stem
        rows.append({"session_id": f"schonlau-{user}-baseline", "username": user, "role": "unknown", "label": "benign", "split": "train", "source": "schonlau_masquerade", "commands": commands[:5000]})
        for block_index in range(100):
            contaminated = matrix[block_index][user_index] == 1
            start = 5000 + block_index * 100
            rows.append({"session_id": f"schonlau-{user}-block-{block_index + 1:03}", "username": user, "role": "unknown", "label": "masquerade" if contaminated else "benign", "split": "test", "source": "schonlau_masquerade", "block_index": block_index + 1, "commands": commands[start:start + 100]})
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command_dir", type=Path, help="directory containing the 50 extracted user files")
    parser.add_argument("locations", type=Path, help="official 100 x 50 contamination matrix")
    parser.add_argument("--output", type=Path, default=Path("data/schonlau_sessions.jsonl"))
    args = parser.parse_args()
    rows = convert(args.command_dir.glob("*"), args.locations, args.output)
    print(f"Wrote {len(rows)} records to {args.output}")


if __name__ == "__main__":
    main()
