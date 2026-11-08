"""Synthetic cold-start curve using session-separated profile training.

Thresholds use benign validation sessions; results use held-out benign and
hijack sessions. This is a controlled generator experiment, not field accuracy.
"""
import json, math, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from czt.brain.profile import MarkovProfile
from czt.brain.tokenizer import tokenize

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/"data/generated_sessions.jsonl"
OUT=Path(__file__).resolve().parents[1]/"results"

def score(model, commands):
    history=[]; values=[]
    for command in commands:
        token=tokenize(command)["token"]
        values.append(-math.log(max(1e-8, model.probability(history, token, include_role=True))))
        history=(history+[token])[-2:]
    return sum(values)/max(1,len(values))

def pct95(values):
    values=sorted(values)
    return values[min(len(values)-1, math.ceil(.95*len(values))-1)]

def fit(rows, role_prior=None):
    model=MarkovProfile(role_prior=role_prior)
    for row in rows:
        history=[]
        for command in row["commands"]:
            token=tokenize(command)["token"]; model.observe(history,token); history=(history+[token])[-2:]
    return model

def run(data_path=DATA,out_dir=OUT,make_plot=True,quiet=False):
    sessions=[json.loads(line) for line in Path(data_path).read_text(encoding="utf-8").splitlines() if line]
    # The generator has one synthetic identity per role. For the zero-session
    # point, approximate a role prior using pooled training traffic from the
    # other roles and disclose this limitation in the result.
    levels=[0,5,20,100]; results={"synthetic_only":True,"seed":sessions[0].get("seed",73) if sessions else 73,"split_unit":"session","target_fpr":.05,"zero_session_prior":"pooled training traffic proxy; only one identity is present per role","models":{},"raw_predictions":{}}
    for n in levels:
        predictions=[]
        for role in sorted({r["role"] for r in sessions if r["label"]=="benign"}):
            pooled=MarkovProfile()
            for other in sessions:
                if other["role"]!=role and other["label"]=="benign" and other["split"]=="train":
                    history=[]
                    for command in other["commands"]:
                        token=tokenize(command)["token"]; pooled.observe(history,token); history=(history+[token])[-2:]
            train=[r for r in sessions if r["role"]==role and r["label"]=="benign" and r["split"]=="train"][:n]
            model=fit(train,pooled.serialize())
            validation=[r for r in sessions if r["role"]==role and r["label"]=="benign" and r["split"]=="validation"]
            threshold=pct95([score(model,r["commands"]) for r in validation])
            heldout=[r for r in sessions if r["role"]==role and r["split"]=="test" and r["label"] in {"benign","hijack"}]
            predictions.extend({"session_id":r["session_id"],"role":role,"label":r["label"],"score":score(model,r["commands"]),"threshold":threshold,"flag":score(model,r["commands"])>threshold} for r in heldout)
        benign=[p for p in predictions if p["label"]=="benign"]
        hijack=[p for p in predictions if p["label"]=="hijack"]
        results["models"][str(n)]={"training_sessions_per_user":n,"test_benign":len(benign),"test_hijack":len(hijack),"false_positive_rate":sum(p["flag"] for p in benign)/len(benign),"hijack_detection_rate":sum(p["flag"] for p in hijack)/len(hijack)}
        results["raw_predictions"][str(n)]=predictions
    out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    (out_dir/"cold_start_summary.json").write_text(json.dumps({k:v for k,v in results.items() if k!="raw_predictions"},indent=2)+"\n",encoding="utf-8")
    (out_dir/"cold_start_raw.json").write_text(json.dumps(results["raw_predictions"],indent=2)+"\n",encoding="utf-8")
    try:
        if not make_plot: return results
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs=levels; detection=[results["models"][str(n)]["hijack_detection_rate"] for n in levels]
        fpr=[results["models"][str(n)]["false_positive_rate"] for n in levels]
        fig,ax=plt.subplots(figsize=(7,4)); ax.plot(xs,detection,marker="o",label="hijack detection")
        ax.plot(xs,fpr,marker="o",label="benign false positives"); ax.axhline(.05,color="#666",linestyle="--",label="5% target")
        ax.set(xlabel="Training sessions per user",ylabel="Held-out rate",ylim=(-.03,1.03),title="Synthetic cold-start curve")
        ax.grid(alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(out_dir/"cold_start.png",dpi=150); plt.close(fig)
    except ImportError:
        pass
    if not quiet: print(json.dumps(results,indent=2))
    return results

if __name__=="__main__": run()
