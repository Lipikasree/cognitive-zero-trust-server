"""Validation-selected, block-level evaluation on official Schonlau traces.

Profiles use each user's complete first 5,000 clean commands. Later 100-command
blocks are split by block index (20% validation, 80% untouched test), so no
commands from a block cross a split. Output files go under eval/results/.
"""
from __future__ import annotations
import csv, json, math, random, sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from czt.brain.tokenizer import tokenize

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/"data"/"schonlau_sessions.jsonl"
OUT=ROOT/"eval"/"results"
SEED=20261103
FPRS=(.01,.05,.10)

def fit(tokens):
    counts=[defaultdict(lambda:defaultdict(float)) for _ in range(3)]
    totals=[defaultdict(float) for _ in range(3)]
    vocab=set(); history=[]
    for token in tokens:
        vocab.add(token)
        for order in range(3):
            if order and len(history)<order: continue
            context=tuple(history[-order:]) if order else ()
            counts[order][context][token]+=1; totals[order][context]+=1
        history=(history+[token])[-2:]
    return {"counts":counts,"totals":totals,"vocab":vocab}

def probabilities(model, history, token, alpha):
    v=max(2,len(model["vocab"]|{token})); result=[]
    for order in range(3):
        context=tuple(history[-order:]) if order else ()
        n=model["totals"][order].get(context,0.0)
        result.append((model["counts"][order].get(context,{}).get(token,0.0)+alpha)/(n+alpha*v))
    return result

def command_losses(tokens,user_model,global_model,alpha,mode,weights):
    losses=[]; history=[]
    for token in tokens:
        up=probabilities(user_model,history,token,alpha)
        gp=probabilities(global_model,history,token,alpha)
        if mode=="interpolated": p=sum(w*x for w,x in zip(weights,up))
        elif mode=="frequency": p=up[0]
        elif mode=="global": p=gp[2]
        elif mode=="likelihood_ratio":
            losses.append(math.log(max(gp[2],1e-12))-math.log(max(up[2],1e-12)))
            history=(history+[token])[-2:]; continue
        else: p=up[2]
        losses.append(-math.log(max(p,1e-12)))
        history=(history+[token])[-2:]
    return losses

def aggregate(losses,kind,window=20,baseline=0.0):
    if kind=="mean": return sum(losses)/max(1,len(losses))
    if kind=="max_window": return max(sum(losses[i:i+window])/len(losses[i:i+window]) for i in range(0,max(1,len(losses)-window+1),max(1,window//2)))
    running=peak=0.0
    for value in losses:
        running=max(0.0,running+value-baseline); peak=max(peak,running)
    return peak/max(1,len(losses))

def auc(labels,scores):
    pairs=sorted(zip(scores,labels)); n1=sum(labels); n0=len(labels)-n1
    if not n1 or not n0: return float("nan")
    rank_sum=0.0; i=0
    while i<len(pairs):
        j=i+1
        while j<len(pairs) and pairs[j][0]==pairs[i][0]: j+=1
        avg_rank=((i+1)+j)/2
        rank_sum+=avg_rank*sum(label for _,label in pairs[i:j]); i=j
    return (rank_sum-n1*(n1+1)/2)/(n1*n0)

def threshold_at_fpr(benign,target):
    ordered=sorted(benign); allowed=math.floor(target*len(ordered)+1e-12)
    return ordered[len(ordered)-allowed-1] if allowed<len(ordered) else float("-inf")

def rate(labels,scores,threshold):
    pred=[score>threshold for score in scores]
    pos=max(1,sum(labels)); neg=max(1,len(labels)-sum(labels))
    return {"detection_rate":sum(p and y for p,y in zip(pred,labels))/pos,
            "false_positive_rate":sum(p and not y for p,y in zip(pred,labels))/neg}

def main():
    random.seed(SEED)
    if not DATA.exists(): raise SystemExit("Missing data/schonlau_sessions.jsonl; see data/EXTERNAL_DATA.md")
    rows=[json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows: row["_tokens"]=[tokenize(command)["token"] for command in row["commands"]]
    users=sorted(r["username"] for r in rows if r["split"]=="train")
    profiles={u:fit(next(r["_tokens"] for r in rows if r["split"]=="train" and r["username"]==u)[:5000]) for u in users}
    global_model=fit([token for r in rows if r["split"]=="train" for token in r["_tokens"][:5000]])
    blocks=[r for r in rows if r["split"]=="test"]
    validation=[r for r in blocks if (int(r["block_index"])-1)%5==0]
    test=[r for r in blocks if (int(r["block_index"])-1)%5!=0]
    assert not ({r["session_id"] for r in validation}&{r["session_id"] for r in test})

    configurations=[]
    for alpha in (.1,.5,1.,2.):
        configurations.append(("per_user_2nd",alpha,"second",(0,0,1)))
        configurations.append(("per_user_frequency",alpha,"frequency",(1,0,0)))
        for weights in ((.60,.30,.10),(.25,.50,.25),(.20,.30,.50)):
            configurations.append(("interpolated",alpha,"interpolated",weights))
        configurations.append(("likelihood_ratio",alpha,"likelihood_ratio",(0,0,1)))
        configurations.append(("global",alpha,"global",(0,0,1)))

    def score_rows(subset,config,aggregation,baseline=0.0):
        name,alpha,mode,weights=config; result=[]
        for row in subset:
            loss=command_losses(row["_tokens"],profiles[row["username"]],global_model,alpha,mode,weights)
            result.append({"session_id":row["session_id"],"username":row["username"],"block_index":row["block_index"],"label":row["label"],"score":aggregate(loss,aggregation,baseline=baseline)})
        return result

    evaluated=[]
    for config in configurations:
        for aggregation in ("mean","max_window","cusum"):
            val0=score_rows(validation,config,aggregation)
            benign=[r["score"] for r in val0 if r["label"]=="benign"]
            baseline=sum(benign)/max(1,len(benign)) if aggregation=="cusum" else 0.0
            # Re-score CUSUM with its validation-only reference level.
            if aggregation=="cusum": val0=score_rows(validation,config,aggregation,baseline)
            labels=[int(r["label"]=="masquerade") for r in val0]; scores=[r["score"] for r in val0]
            t=threshold_at_fpr([r["score"] for r in val0 if r["label"]=="benign"],.05)
            det=rate(labels,scores,t)["detection_rate"]
            evaluated.append({"config":config,"aggregation":aggregation,"baseline":baseline,"validation_detection_at_5pct_fpr":det,"validation_auc":auc(labels,scores),"validation_scores":val0})
    selected={}
    for family in sorted({x["config"][0] for x in evaluated}):
        choices=[x for x in evaluated if x["config"][0]==family]
        selected[family]=max(choices,key=lambda x:(x["validation_detection_at_5pct_fpr"],x["validation_auc"]))

    output={"seed":SEED,"dataset":"Schonlau masquerade command traces","command_content":"Unix command names only; arguments are not present in the source dataset.","protocol":{"training_commands_per_user":5000,"block_size":100,"validation_blocks_per_user":20,"test_blocks_per_user":80,"validation_rule":"block_index 1,6,...,96; session-level split by complete 100-command block","thresholds":"selected only from benign validation blocks","users":len(users)},"models":{},"roc":{}}
    raw={"validation":{},"test":{}}
    roc_rows=[]
    for family,choice in selected.items():
        config=choice["config"]; aggregation=choice["aggregation"]; baseline=choice["baseline"]
        val=choice["validation_scores"]; tst=score_rows(test,config,aggregation,baseline)
        y=[int(r["label"]=="masquerade") for r in tst]; s=[r["score"] for r in tst]
        benign=[r["score"] for r in val if r["label"]=="benign"]
        metrics={"auc":auc(y,s),"selected_on_validation":{"alpha":config[1],"aggregation":aggregation,"interpolation_weights":config[3],"validation_auc":choice["validation_auc"],"validation_detection_at_5pct_fpr":choice["validation_detection_at_5pct_fpr"]},"test_blocks":len(tst),"test_masquerade_blocks":sum(y),"at_fpr":{}}
        for target in FPRS:
            threshold=threshold_at_fpr(benign,target)
            metrics["at_fpr"][str(int(target*100))+"%"]={"validation_threshold":threshold,**rate(y,s,threshold)}
        output["models"][family]=metrics
        raw["validation"][family]=val; raw["test"][family]=tst
        # Full ROC curve (group ties at each unique score).
        points=[{"fpr":0.0,"tpr":0.0}]
        for value in sorted(set(s),reverse=True):
            pred=[score>=value for score in s]
            points.append({"fpr":sum(p and not label for p,label in zip(pred,y))/max(1,len(y)-sum(y)),"tpr":sum(p and label for p,label in zip(pred,y))/max(1,sum(y))})
        output["roc"][family]=points
        roc_rows.extend({"method":family,"fpr":p["fpr"],"tpr":p["tpr"]} for p in points)

    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"schonlau_summary.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    (OUT/"schonlau_raw.json").write_text(json.dumps(raw,indent=2)+"\n",encoding="utf-8")
    with (OUT/"schonlau_summary.csv").open("w",newline="",encoding="utf-8") as f:
        writer=csv.writer(f); writer.writerow(["method","auc","detection_at_1pct_fpr","detection_at_5pct_fpr","detection_at_10pct_fpr","test_fpr_at_1pct_threshold","test_fpr_at_5pct_threshold","test_fpr_at_10pct_threshold","selected_config"])
        for name,m in output["models"].items():
            writer.writerow([name,m["auc"],*[m["at_fpr"][f"{p}%"]["detection_rate"] for p in (1,5,10)],*[m["at_fpr"][f"{p}%"]["false_positive_rate"] for p in (1,5,10)],json.dumps(m["selected_on_validation"])])
    with (OUT/"schonlau_roc.csv").open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=["method","fpr","tpr"]); writer.writeheader(); writer.writerows(roc_rows)
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig,ax=plt.subplots(figsize=(7,6))
        for name,points in output["roc"].items(): ax.plot([p["fpr"] for p in points],[p["tpr"] for p in points],label=f"{name} (AUC={output['models'][name]['auc']:.3f})")
        for x in FPRS: ax.axvline(x,color="#aaa",linestyle=":",linewidth=.8)
        ax.plot([0,1],[0,1],color="#777",linestyle="--",linewidth=.8); ax.set(xlim=(0,1),ylim=(0,1),xlabel="False-positive rate",ylabel="Detection rate",title="Schonlau held-out 100-command blocks")
        ax.grid(alpha=.2); ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(OUT/"schonlau_roc.png",dpi=160); plt.close(fig)
    except ImportError: pass
    (ROOT/"eval"/"schonlau_results.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(output["models"],indent=2))

if __name__=="__main__": main()
