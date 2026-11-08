"""Compare target SSH exec with the gateway SSH path using AsyncSSH."""
import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import asyncssh


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parents[1] / "results" / "latency_raw.json"


async def sample(host, port, username, key_path, known_hosts, count):
    values = []
    for _ in range(count):
        start = time.perf_counter()
        async with asyncssh.connect(host, port=port, username=username, client_keys=[str(key_path)], known_hosts=known_hosts, login_timeout=10) as connection:
            result = await connection.run("whoami", check=True)
            if not result.stdout.strip():
                raise RuntimeError("SSH command returned no output")
        values.append((time.perf_counter() - start) * 1000)
    return values


def summarize(values):
    ordered = sorted(values)
    return {"iterations": len(values), "median_ms": round(statistics.median(values), 3), "mean_ms": round(statistics.mean(values), 3), "p95_ms": round(ordered[int(.95 * (len(ordered) - 1))], 3), "samples_ms": [round(value, 3) for value in values]}


async def inside(iterations):
    return await sample("target", 22, "czt-demo", "/app/keys/upstream", "/app/keys/upstream_known_hosts", iterations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    iterations = args.iterations or int(os.environ.get("CZTS_BENCH_ITERATIONS", "10"))
    if iterations < 3:
        parser.error("use at least 3 iterations")
    if args.inside:
        print(json.dumps({"direct_target_samples_ms": asyncio.run(inside(iterations))}))
        return

    compose = ["docker", "compose", "--env-file", ".env", "-f", "deploy/docker-compose.yml", "--profile", "benchmark", "run", "--rm", "-T", "-e", f"CZTS_BENCH_ITERATIONS={iterations}", "direct-probe"]
    direct_result = subprocess.run(compose, cwd=ROOT, capture_output=True, text=True, timeout=240)
    if direct_result.returncode:
        raise SystemExit(f"Direct-target probe failed: {direct_result.stderr.strip()}")
    try:
        direct_samples = json.loads(direct_result.stdout.strip().splitlines()[-1])["direct_target_samples_ms"]
    except (IndexError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not parse direct-target probe output: {direct_result.stdout[-1000:]}") from exc
    gateway_samples = asyncio.run(sample("127.0.0.1", 2222, "alice", ROOT / "keys" / "alice_client", None, iterations))
    result = {
        "seed": 20261103,
        "scope": "AsyncSSH connect plus whoami; direct probe runs in a one-shot container on the private network",
        "command": "whoami",
        "direct_target": summarize(direct_samples),
        "through_gateway": summarize(gateway_samples),
        "median_added_ms": round(statistics.median(gateway_samples) - statistics.median(direct_samples), 3),
        "limitation": "Client network contexts differ: the direct probe is a temporary local Docker service; gateway samples originate from Windows. The probe is removed after measurement.",
    }
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (OUT.parent/"latency_summary.json").write_text(json.dumps({k:v for k,v in result.items() if k not in {"direct_target","through_gateway"}},indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig,ax=plt.subplots(figsize=(7,4)); ax.boxplot([direct_samples,gateway_samples],tick_labels=["direct target","through gateway"],showmeans=True)
        ax.set(ylabel="SSH connect + whoami (ms)",title="Direct versus gateway SSH latency"); ax.grid(axis="y",alpha=.25); fig.tight_layout(); fig.savefig(OUT.parent/"latency.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
