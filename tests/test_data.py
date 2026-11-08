import sys, json
from pathlib import Path
from collections import Counter,defaultdict

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from data.generate_sessions import generate
from data.load_cowrie import convert as convert_cowrie
from data.load_schonlau import convert as convert_schonlau

def test_synthetic_sessions_have_unique_session_splits(tmp_path):
    rows=generate(seed=73,output=tmp_path/"sessions.jsonl")
    assert len({r["session_id"] for r in rows})==len(rows)
    groups=defaultdict(Counter)
    for row in rows: groups[(row["role"],row["label"])][row["split"]]+=1
    assert groups[("developer","benign")] == Counter(train=102,validation=34,test=34)
    assert groups[("unknown","attack")] == Counter(train=24,validation=8,test=8)
    assert all(row["source"]=="synthetic_generator" for row in rows)


def test_cowrie_loader_groups_and_splits_whole_sessions(tmp_path):
    source = tmp_path / "cowrie.json"
    events = [
        {"eventid":"cowrie.command.input","session":"a","timestamp":"2024-01-01T00:00:02Z","input":"whoami"},
        {"eventid":"cowrie.command.input","session":"a","timestamp":"2024-01-01T00:00:01Z","input":"pwd"},
        {"eventid":"cowrie.command.input","session":"a","timestamp":"2024-01-01T00:00:03Z","input":"answer","realm":"passwd"},
        {"eventid":"cowrie.login.failed","session":"a","password":"do-not-ingest"},
    ]
    events.extend({"eventid":"cowrie.command.input","session":f"s{i}","timestamp":"2024-01-01T00:00:00Z","input":"id"} for i in range(10))
    source.write_text("".join(json.dumps(event)+"\n" for event in events), encoding="utf-8")
    output = tmp_path / "converted.jsonl"
    rows = convert_cowrie([source], output, seed=4)
    row = next(item for item in rows if item["commands"] == ["pwd", "whoami"])
    assert row["source"] == "cowrie_jsonl"
    assert row["label"] == "attack"
    assert len({item["split"] for item in rows if item["session_id"].startswith("cowrie-")}) == 3
    assert "do-not-ingest" not in output.read_text(encoding="utf-8")


def test_schonlau_loader_creates_baseline_and_labeled_blocks(tmp_path):
    command_dir = tmp_path / "commands"
    command_dir.mkdir()
    files = []
    for i in range(50):
        path = command_dir / f"User{i + 1}"
        path.write_text("".join(f"cmd{n}\n" for n in range(15000)), encoding="utf-8")
        files.append(path)
    locations = tmp_path / "locations.txt"
    matrix = [[1 if user == 0 and block == 0 else 0 for user in range(50)] for block in range(100)]
    locations.write_text("\n".join(" ".join(map(str, row)) for row in matrix), encoding="utf-8")
    rows = convert_schonlau(files, locations, tmp_path / "out.jsonl")
    assert len(rows) == 50 * 101
    assert len(rows[0]["commands"]) == 5000
    first_user_blocks = [row for row in rows if row["username"] == "User1" and row["split"] == "test"]
    assert first_user_blocks[0]["label"] == "masquerade"
    assert first_user_blocks[0]["commands"] == [f"cmd{i}" for i in range(5000, 5100)]
    assert sum(row["label"] == "masquerade" for row in rows) == 1
