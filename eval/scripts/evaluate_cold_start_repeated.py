"""Repeat the 0/5/20/100 synthetic cold-start curve across generator seeds."""
import json, statistics, tempfile, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent)); sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from data.generate_sessions import generate
from evaluate_cold_start import run
OUT=Path(__file__).resolve().parents[1]/"results"; SEEDS=(73,74,75,76,77)

def main():
    runs=[]
    with tempfile.TemporaryDirectory(prefix="czts-cold-") as temp:
        root=Path(temp)
        for seed in SEEDS:
            data=root/f"sessions-{seed}.jsonl"; folder=root/f"run-{seed}"
            generate(seed=seed,output=data); runs.append({"seed":seed,"results":run(data,folder,make_plot=False,quiet=True)})
    summary={}
    for n in (0,5,20,100):
        summary[str(n)]={}
        for metric in ("hijack_detection_rate","false_positive_rate"):
            vals=[x["results"]["models"][str(n)][metric] for x in runs]
            summary[str(n)][metric]={"mean":statistics.mean(vals),"stdev":statistics.stdev(vals),"per_seed":vals}
    results={"synthetic_only":True,"split_unit":"session","seeds":list(SEEDS),"summary":summary,"runs":runs}
    (OUT/"cold_start_repeated_summary.json").write_text(json.dumps({"synthetic_only":True,"split_unit":"session","seeds":list(SEEDS),"summary":summary},indent=2)+"\n",encoding="utf-8")
    (OUT/"cold_start_repeated_raw.json").write_text(json.dumps([{"seed":x["seed"],"training_sessions_per_user":n,"predictions":x["results"]["raw_predictions"][str(n)]} for x in runs for n in (0,5,20,100)],indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig,ax=plt.subplots(figsize=(7,4)); xs=[0,5,20,100]
        for metric,label in (("hijack_detection_rate","hijack detection"),("false_positive_rate","benign false positives")):
            means=[summary[str(n)][metric]["mean"] for n in xs]; dev=[summary[str(n)][metric]["stdev"] for n in xs]
            ax.errorbar(xs,means,yerr=dev,marker="o",capsize=4,label=f"{label} ± sample SD")
        ax.axhline(.05,color="#666",linestyle="--",label="5% target"); ax.set(xlabel="Training sessions per user",ylabel="Held-out rate",ylim=(-.03,1.03),title="Five-seed synthetic cold-start evaluation")
        ax.grid(alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(OUT/"cold_start_repeated.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps(summary,indent=2))

if __name__=="__main__": main()
