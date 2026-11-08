"""Run synthetic hijacks through Session.evaluate and compare a counter baseline."""
import asyncio, json, statistics, tempfile, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from data.generate_sessions import generate
from czt.brain.engine import Engine, Session
from czt.brain.rules import evaluate
from czt.brain.trust import Trust
from czt.store import Store

ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"
SETTINGS=json.loads((ROOT/"config/settings.json").read_text(encoding="utf-8")); SEEDS=(73,74,75,76,77)

class Writer:
    def write(self,event): return event
class FakeProcess:
    def __init__(self): self.stdout=self; self.stdin=self
    def write(self,data): pass
    async def drain(self): pass
    async def readline(self): return b"NO\n"
    def get_extra_info(self,name): return ("synthetic",0)

def train(store,rows):
    from czt.brain.profile import MarkovProfile
    from czt.brain.tokenizer import tokenize
    users={}
    for row in rows:
        if row["split"]!="train" or row["label"]!="benign": continue
        model=users.setdefault(row["username"],MarkovProfile()); history=[]
        for command in row["commands"]:
            token=tokenize(command)["token"]; model.observe(history,token); history=(history+[token])[-2:]
    for username,model in users.items(): store.save_profile(username,model.serialize())

async def run_seed(seed,root):
    data=root/f"sessions-{seed}.jsonl"; rows=generate(seed=seed,output=data)
    store=Store(str(root/f"judgment-{seed}.sqlite3")); train(store,rows); engine=Engine(store,Writer(),SETTINGS,prior_path=data)
    results=[]
    for row in rows:
        if row["split"]!="test" or row["label"]!="hijack": continue
        sid=f"{seed}-{row['session_id']}"; store.start_session(sid,row["username"],"synthetic")
        session=Session(engine,sid,row["username"],row["role"]); process=FakeProcess(); first_restricted=None; first_discarded=None; counter_count=0; counter_restricted=None; counter_discarded=None
        for seq,command in enumerate(row["commands"],1):
            decision,event=await session.evaluate(command,process)
            if session.state=="restricted" and first_restricted is None: first_restricted=seq
            if session.state=="discarded" and first_discarded is None: first_discarded=seq
            counter_count+=len(evaluate(command))
            if counter_count>=1 and counter_restricted is None: counter_restricted=seq
            if counter_count>=3 and counter_discarded is None: counter_discarded=seq
            if decision=="discard": break
        session.finish()
        results.append({"session_id":row["session_id"],"role":row["role"],"commands":len(row["commands"]),"belief_restricted_at":first_restricted,"belief_discarded_at":first_discarded,"counter_restricted_at":counter_restricted,"counter_discarded_at":counter_discarded,"final_state":session.state})
    store.close(); return {"seed":seed,"hijack_sessions":results}

async def main():
    with tempfile.TemporaryDirectory(prefix="czts-judgment-") as temp:
        runs=[await run_seed(seed,Path(temp)) for seed in SEEDS]
    rows=[row for run in runs for row in run["hijack_sessions"]]
    summary={}
    for key in ("belief_restricted_at","belief_discarded_at","counter_restricted_at","counter_discarded_at"):
        vals=[row[key] for row in rows if row[key] is not None]
        summary[key]={"observed_sessions":len(vals),"mean_commands":statistics.mean(vals) if vals else None,"median_commands":statistics.median(vals) if vals else None}
    result={"synthetic_only":True,"engine_path":"actual Session.evaluate, Trust, Policy, rules, and SQLite Store","seeds":list(SEEDS),"counter_baseline":"rule-hit count; restrict at 1 hit and discard at 3","hijack_session_count":len(rows),"summary":summary,"runs":runs}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"judgment_raw.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/"judgment_summary.json").write_text(json.dumps({k:v for k,v in result.items() if k!="runs"},indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        names=("belief_restricted_at","counter_restricted_at","belief_discarded_at","counter_discarded_at")
        data=[[row[name] for row in rows if row[name] is not None] for name in names]
        fig,ax=plt.subplots(figsize=(8,4)); ax.boxplot(data,tick_labels=[n.replace("_at","").replace("_"," ") for n in names],showmeans=True)
        ax.set(ylabel="Commands from hijack start",title="Five-seed synthetic hijack response through the actual engine"); ax.grid(axis="y",alpha=.25); fig.tight_layout(); fig.savefig(OUT/"judgment.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps({"hijack_session_count":len(rows),"summary":summary},indent=2))

if __name__=="__main__": asyncio.run(main())
