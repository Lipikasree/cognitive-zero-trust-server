"""Repeat the synthetic personalization evaluation with independent generator seeds."""
import json, statistics, tempfile, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from data.generate_sessions import generate
from evaluate import run

OUT=Path(__file__).resolve().parents[1]/"results"; SEEDS=(73,74,75,76,77)

def main():
    runs=[]; raw_scores=[]
    with tempfile.TemporaryDirectory(prefix="czts-repeat-") as temp:
        root=Path(temp)
        for seed in SEEDS:
            data=root/f"sessions-{seed}.jsonl"; folder=root/f"run-{seed}"
            generate(seed=seed,output=data); result=run(data,folder,make_plot=False,quiet=True)
            runs.append({"seed":seed,"results":result})
            scores=json.loads((folder/"synthetic_raw.json").read_text(encoding="utf-8"))
            for model,rows in scores.items():
                raw_scores.extend({"seed":seed,"model":model,**row} for row in rows)
    summary={}
    for model in ("per_user","global"):
        for metric in ("test_detection_rate","test_false_positive_rate"):
            vals=[runrow["results"]["models"][model][metric] for runrow in runs]
            summary.setdefault(model,{})[metric]={"mean":statistics.mean(vals),"stdev":statistics.stdev(vals),"per_seed":vals}
    result={"synthetic_only":True,"split_unit":"session","seeds":list(SEEDS),"summary":summary,"runs":runs}
    (OUT/"personalization_summary.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/"personalization_raw.json").write_text(json.dumps(raw_scores,indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig,axes=plt.subplots(1,2,figsize=(10,4))
        for ax,metric,title in ((axes[0],"test_detection_rate","Held-out masquerade detection"),(axes[1],"test_false_positive_rate","Held-out benign false positives")):
            for model,color in (("per_user","#287271"),("global","#e76f51")):
                means=[summary[model][metric]["mean"]]; dev=[summary[model][metric]["stdev"]]
                ax.bar(model,means[0],yerr=dev[0],color=color,capsize=4,label=f"{model} ± sample SD")
            ax.set(title=title,ylabel="Rate",ylim=(0,1)); ax.grid(axis="y",alpha=.25)
        fig.suptitle(f"Five synthetic session-separated runs (seeds {SEEDS[0]}–{SEEDS[-1]})"); fig.tight_layout(); fig.savefig(OUT/"personalization.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps({"seeds":SEEDS,"summary":summary},indent=2))

if __name__=="__main__": main()
