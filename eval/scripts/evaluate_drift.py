"""Ten-seed, three-arm profile-drift experiment through the production engine."""
import asyncio, csv, json, random, statistics, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from czt.brain.engine import Engine, Session
from czt.brain.learn import label_session, promote_quarantine
from czt.brain.profile import MarkovProfile
from czt.store import Store
from data.generate_sessions import generate

ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"; SEEDS=tuple(range(73,83)); BOOTSTRAP_SEED=20261103
SETTINGS=json.loads((ROOT/"config/settings.json").read_text(encoding="utf-8"))
class NullWriter:
    def write(self,event): return event
class FakeProcess:
    def __init__(self): self.stdout=self; self.stdin=self
    def write(self,data): pass
    async def drain(self): pass
    async def readline(self): return b"NO\n"
    def get_extra_info(self,name): return ("synthetic",0)

def train_profiles(store,rows):
    profiles={}
    from czt.brain.tokenizer import tokenize
    for row in rows:
        if row["split"]!="train" or row["label"]!="benign": continue
        profile=profiles.setdefault(row["role"],MarkovProfile()); history=[]
        for command in row["commands"]:
            token=tokenize(command)["token"]; profile.observe(history,token); history=(history+[token])[-2:]
    for role,profile in profiles.items(): store.save_profile(role,profile.serialize())

async def one_session(engine,store,row,seed,role,index,arm):
    sid=f"{seed}-{role}-{row['drift_type']}-{index}-{arm}"; store.start_session(sid,role,"synthetic")
    session=Session(engine,sid,role,role); process=FakeProcess(); blocked=0; surprises=[]; states=[]
    for command in row["commands"]:
        decision,event=await session.evaluate(command,process)
        surprises.append(float(event.get("surprise",0))); states.append(event.get("state"))
        blocked+=decision in {"block","discard"}
        if decision=="discard": break
    session.finish(); feedback=None
    if arm=="feedback" and (session.state!="allowed" or blocked):
        label_session(store,sid,"false_positive",event_sink=engine.events); feedback="admin_false_positive"
    elif arm in {"automatic","feedback"}:
        # Time moves beyond quarantine maturity; only the engine's eligible
        # allowed, rule-free sessions are promoted.
        promote_quarantine(store,now=time.time()+3600,event_sink=engine.events)
    record=store.get_session(sid)
    return {"seed":seed,"role":role,"drift_type":row["drift_type"],"session_order":index+1,"session_id":row["session_id"],"arm":arm,"final_state":record["final_state"],"commands_seen":len(surprises),"commands_blocked":blocked,"mean_command_surprise":statistics.mean(surprises) if surprises else 0.0,"score_trajectory":surprises,"state_trajectory":states,"feedback":feedback,"quarantine_status":(store.db.execute("SELECT status FROM quarantine WHERE session_id=?",(sid,)).fetchone() or [None])[0]}

async def run_seed(seed,root):
    data_path=root/f"sessions-{seed}.jsonl"; rows=generate(seed=seed,output=data_path)
    drift=[{**r,"drift_type":"gradual"} for r in rows if r["label"]=="drift" and r["split"]=="test"]
    from data.generate_sessions import DRIFT
    rng=random.Random(seed+999)
    clear=[]
    for row in drift:
        commands=[rng.choice(DRIFT[row["role"]]) for _ in row["commands"]]
        clear.append({**row,"session_id":row["session_id"]+"-clear","commands":commands,"drift_type":"clear"})
    drift.extend(clear)
    output=[]
    for arm in ("static","automatic","feedback"):
        for role in sorted({r["role"] for r in drift}):
            for drift_type in ("gradual","clear"):
                store=Store(str(root/f"{seed}-{role}-{drift_type}-{arm}.sqlite3")); train_profiles(store,rows)
                engine=Engine(store,NullWriter(),SETTINGS,prior_path=data_path)
                try:
                    for index,row in enumerate(r for r in drift if r["role"]==role and r["drift_type"]==drift_type):
                        output.append(await one_session(engine,store,row,seed,role,index,arm))
                finally: store.close()
    return output

def ci95(values,rng,replicates=10000):
    means=[]; n=len(values)
    for _ in range(replicates): means.append(statistics.mean(rng.choices(values,k=n)))
    means.sort(); return means[int(.025*replicates)],means[min(replicates-1,int(.975*replicates))]

async def main():
    random.seed(BOOTSTRAP_SEED); all_rows=[]
    with tempfile.TemporaryDirectory(prefix="czts-drift-") as temp:
        root=Path(temp)
        for seed in SEEDS: all_rows.extend(await run_seed(seed,root))
    roles=sorted({r["role"] for r in all_rows}); arms=("static","automatic","feedback"); drift_types=("gradual","clear")
    grouped={}
    for role in roles:
        grouped[role]={}
        for drift_type in drift_types:
            grouped[role][drift_type]={}
            for arm in arms:
                sub=[r for r in all_rows if r["role"]==role and r["drift_type"]==drift_type and r["arm"]==arm]
                seed_rates=[]
                for seed in SEEDS:
                    rows=[r for r in sub if r["seed"]==seed]
                    seed_rates.append(sum(r["final_state"]!="allowed" or r["commands_blocked"]>0 for r in rows)/max(1,len(rows)))
                avg=statistics.mean(seed_rates); lo,hi=ci95(seed_rates,random.Random(BOOTSTRAP_SEED+len(role)+len(arm)+len(drift_type)))
                grouped[role][drift_type][arm]={"mean_false_positive_rate":avg,"ci95_bootstrap":[lo,hi],"per_seed":seed_rates,"eligible_released":sum(r["quarantine_status"]=="released" for r in sub),"sessions":len(sub)}
    trajectory=[]
    for role in roles:
        for drift_type in drift_types:
            for arm in arms:
                sub=[r for r in all_rows if r["role"]==role and r["drift_type"]==drift_type and r["arm"]==arm]
                for step in range(1,5):
                    selected=[r["mean_command_surprise"] for r in sub if r["session_order"]==step]
                    trajectory.append({"role":role,"drift_type":drift_type,"arm":arm,"session_order":step,"mean_command_surprise":statistics.mean(selected) if selected else 0.0,"n":len(selected)})
    summary={"synthetic_only":True,"seed":BOOTSTRAP_SEED,"seeds":list(SEEDS),"split_unit":"whole generated session","drift_scenarios":{"gradual":"three new-tool commands inserted into the user's usual command list","clear":"all commands in the drift session come from the changed tool family"},"profile_forgetting_factor":SETTINGS["profile_forgetting_factor"],"quarantine_delay_seconds":SETTINGS["quarantine_delay_seconds"],"automatic_arm_simulated_wait_seconds":3600,"arms":{"static":"no updates","automatic":"automatic delayed promotion of eligible clean sessions only","feedback":"automatic promotion plus admin false-positive label when a known-benign drift session is restricted or blocked"},"role_summary":grouped,"trajectory":trajectory,"limitations":"Synthetic labels are known to the harness. Feedback uses oracle-known benign labels to model administrator review; this is an optimistic upper bound. Automatic updates cannot learn restricted sessions under the existing eligibility guard. Forgetting-factor tuning is not included; the configured factor is recorded above. Results do not establish production drift performance."}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"drift_raw.json").write_text(json.dumps(all_rows,indent=2)+"\n",encoding="utf-8")
    (OUT/"drift_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    with (OUT/"drift_summary.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["role","drift_type","arm","mean_fpr","ci95_low","ci95_high","sessions","eligible_released"])
        for role in roles:
            for drift_type in drift_types:
                for arm in arms:
                    d=grouped[role][drift_type][arm]; w.writerow([role,drift_type,arm,d["mean_false_positive_rate"],*d["ci95_bootstrap"],d["sessions"],d["eligible_released"]])
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig,axes=plt.subplots(1,2,figsize=(12,4.5))
        colors={"static":"#457b9d","automatic":"#e9c46a","feedback":"#2a9d8f"}
        for ax,drift_type in zip(axes,("gradual","clear")):
            for arm in arms:
                values=[statistics.mean([x["mean_command_surprise"] for x in all_rows if x["drift_type"]==drift_type and x["arm"]==arm and x["session_order"]==step]) for step in range(1,5)]
                ax.plot(range(1,5),values,marker="o",color=colors[arm],label=arm)
            ax.set(xlabel="Drift session order",ylabel="Mean per-command surprise",title=f"{drift_type.title()} drift score trajectory"); ax.grid(alpha=.25); ax.legend()
        fig.tight_layout(); fig.savefig(OUT/"drift.png",dpi=160); plt.close(fig)
        for drift_type in drift_types:
            names=[]; means=[]; lows=[]; highs=[]
            for role in roles:
                for arm in arms:
                    d=grouped[role][drift_type][arm]; names.append(f"{role}\n{arm}"); means.append(d["mean_false_positive_rate"]); lows.append(d["mean_false_positive_rate"]-d["ci95_bootstrap"][0]); highs.append(d["ci95_bootstrap"][1]-d["mean_false_positive_rate"])
            fig2,ax=plt.subplots(figsize=(10,4)); ax.bar(range(len(names)),means,color=[colors[name.split("\n")[1]] for name in names]); ax.errorbar(range(len(names)),means,yerr=[lows,highs],fmt="none",ecolor="#222",capsize=3)
            ax.set_xticks(range(len(names)),names,rotation=45,ha="right",fontsize=7); ax.set(ylabel="Drift false-positive rate",ylim=(0,1),title=f"{drift_type.title()} drift arms, ten seeds (bootstrap 95% CI)"); ax.grid(axis="y",alpha=.2); fig2.tight_layout(); fig2.savefig(OUT/f"drift_{drift_type}.png",dpi=160); plt.close(fig2)
    except ImportError: pass
    print(json.dumps(grouped,indent=2))

if __name__=="__main__": asyncio.run(main())
