"""Session-separated synthetic masquerade experiment; no production claims."""
import json, math, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from czt.brain.profile import MarkovProfile
from czt.brain.tokenizer import tokenize

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/"data/generated_sessions.jsonl"
OUT=Path(__file__).resolve().parents[1]/"results"

def load_data(path=DATA):
    if not path.exists():
        from data.generate_sessions import generate
        generate(output=path)
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]

def train(sessions):
    users={}; global_model=MarkovProfile()
    for session in sessions:
        if session["label"]!="benign" or session["split"]!="train": continue
        user=session["username"]; model=users.setdefault(user,MarkovProfile()); history=[]
        for command in session["commands"]:
            token=tokenize(command)["token"]; model.observe(history,token); global_model.observe(history,token); history=(history+[token])[-2:]
    return users,global_model

def score(model,commands):
    history=[]; values=[]
    for command in commands:
        token=tokenize(command)["token"]; p=max(1e-8,model.probability(history,token,include_role=False)); values.append(-math.log(p)); history=(history+[token])[-2:]
    return sum(values)/max(len(values),1)

def percentile(values,p):
    values=sorted(values)
    if not values: return 0.0
    idx=min(len(values)-1,max(0,math.ceil(p*len(values))-1)); return values[idx]

def run(data_path=DATA,out_dir=OUT,make_plot=True,quiet=False):
    sessions=load_data(Path(data_path)); users,global_model=train(sessions); seed=sessions[0].get("seed",73) if sessions else 73
    validation=[x for x in sessions if x["split"]=="validation" and x["label"]=="benign"]
    test=[x for x in sessions if x["split"]=="test" and x["label"] in {"benign","hijack","attack"}]
    results={"synthetic_only":True,"seed":seed,"split_unit":"session","validation_benign_sessions":len(validation),"test_sessions":len(test),"models":{}}
    scores_by_model={}
    for name in ("per_user","global"):
        get_model=(lambda x:users.get(x["username"],MarkovProfile())) if name=="per_user" else (lambda x:global_model)
        threshold=percentile([score(get_model(x),x["commands"]) for x in validation],.95)
        rows=[]
        for s in test:
            value=score(get_model(s),s["commands"])
            rows.append({"session_id":s["session_id"],"role":s["role"],"label":s["label"],"score":value,"predicted_masquerade":value>threshold})
        benign=[x for x in rows if x["label"]=="benign"]; malicious=[x for x in rows if x["label"] in {"hijack","attack"}]
        results["models"][name]={"threshold_at_5pct_validation_fpr":threshold,"test_benign":len(benign),"test_malicious":len(malicious),"test_false_positive_rate":sum(x["predicted_masquerade"] for x in benign)/max(len(benign),1),"test_detection_rate":sum(x["predicted_masquerade"] for x in malicious)/max(len(malicious),1)}
        scores_by_model[name]=rows
    results["generated_session_count"]=len(sessions)
    out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    (out_dir/"synthetic_summary.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    (out_dir/"synthetic_raw.json").write_text(json.dumps(scores_by_model,indent=2)+"\n",encoding="utf-8")
    try:
        if not make_plot: return results
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig,axes=plt.subplots(1,2,figsize=(11,4),sharey=True)
        for ax,(name,rows) in zip(axes,scores_by_model.items()):
            for label,color in (("benign","#2a9d8f"),("hijack","#e9c46a"),("attack","#e76f51")):
                vals=[r["score"] for r in rows if r["label"]==label]
                ax.hist(vals,bins=18,alpha=.62,label=label,color=color)
            ax.axvline(results["models"][name]["threshold_at_5pct_validation_fpr"],color="#264653",linestyle="--",label="validation 5% FPR threshold")
            ax.set_title(name.replace("_"," ").title()); ax.set_xlabel("Mean command surprise (nats)"); ax.grid(alpha=.2)
        axes[0].set_ylabel("Held-out sessions"); axes[1].legend(fontsize=8)
        fig.suptitle("Synthetic session masquerade check (not real-world performance)"); fig.tight_layout()
        fig.savefig(out_dir/"synthetic.png",dpi=150); plt.close(fig)
    except ImportError:
        if not quiet: print("Optional matplotlib not installed; score JSON written without plot.")
    if not quiet: print(json.dumps(results,indent=2))
    return results

if __name__=="__main__": run()
