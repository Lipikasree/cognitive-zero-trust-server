"""Temporal holdout of COW160 Cowrie days versus benign synthetic sessions."""
import csv,gzip,json,math,random,re,statistics,sys,hashlib
from collections import defaultdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from czt.brain.profile import MarkovProfile
from czt.brain.tokenizer import tokenize
ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"; RAW=ROOT/"data"/"external_raw"/"cowrie"; SEED=20261103

def read_day(path):
    sessions=defaultdict(list)
    with gzip.open(path,"rt",encoding="utf-8",errors="replace") as stream:
        for line in stream:
            if not line.strip(): continue
            e=json.loads(line)
            if e.get("eventid")!="cowrie.command.input" or e.get("realm"): continue
            sid=e.get("session"); command=e.get("input")
            if not isinstance(sid,str) or not sid or not isinstance(command,str) or not command.strip(): continue
            sensor=str(e.get("sensor","")); key=f"{sensor}:{sid}" if sensor else sid
            sessions[key].append((str(e.get("timestamp",e.get("ts",""))),command.strip()))
    return [[command for _,command in sorted(items,key=lambda x:x[0])] for items in sessions.values() if items]

def observe(profile,commands):
    history=[]
    for command in commands:
        token=tokenize(command)["token"]; profile.observe(history,token); history=(history+[token])[-2:]

def attacker_score(profile,commands):
    history=[]; ll=[]
    for command in commands:
        token=tokenize(command)["token"]; ll.append(math.log(max(profile.probability(history,token,include_role=False),1e-12))); history=(history+[token])[-2:]
    return statistics.mean(ll) if ll else float("-inf")

def threshold(values,fpr=.05):
    s=sorted(values); allowed=math.floor(fpr*len(s)); return s[len(s)-allowed-1]

def main():
    random.seed(SEED)
    files=sorted(RAW.glob("cow160_*.json.gz"))
    if len(files)<6: raise SystemExit(f"Need at least six daily files (one initial plus five additional); found {len(files)}")
    days={path.name.removeprefix("cow160_").removesuffix(".json.gz"):read_day(path) for path in files}
    temporal_rows=[]; train_cut=max(1,len(days)-2)
    for day_index,day in enumerate(sorted(days)):
        for i,commands in enumerate(days[day]):
            sid=hashlib.sha256(f"{day}:{i}".encode()).hexdigest()[:20]
            temporal_rows.append({"session_id":f"cowrie-{day}-{sid}","username":"cowrie_attacker","role":"attacker","label":"attack","split":"train" if day_index<train_cut else "test","source":"cowrie_cow160","day":day,"commands":commands})
    synthetic=[json.loads(x) for x in (ROOT/"data"/"generated_sessions.jsonl").read_text(encoding="utf-8").splitlines() if x]
    benign_val=[r["commands"] for r in synthetic if r["split"]=="validation" and r["label"]=="benign"]
    benign_test=[r["commands"] for r in synthetic if r["split"]=="test" and r["label"]=="benign"]
    results=[]; privacy_checks=[]
    # Expanding temporal folds: train on all earlier Cowrie days and test the
    # next day. No test-day sessions enter training.
    names=sorted(days)
    for test_index in range(1,len(names)):
        test_day=names[test_index]; train_days=names[:test_index]
        profile=MarkovProfile()
        for day in train_days:
            for commands in days[day]: observe(profile,commands)
        serialized=profile.serialize(); privacy_checks.append({"test_day":test_day,"profile_transition_count":len(serialized),"contains_ip_or_url_literals":any(re.search(r"(?:\d{1,3}\.){3}\d{1,3}|https?://",key,re.I) for key in serialized)})
        val_scores=[attacker_score(profile,c) for c in benign_val]
        cut=threshold(val_scores)
        benign_scores=[attacker_score(profile,c) for c in benign_test]
        benign_fpr=sum(x>cut for x in benign_scores)/max(1,len(benign_scores))
        attack_scores=[attacker_score(profile,c) for c in days[test_day]]
        detection=sum(x>cut for x in attack_scores)/max(1,len(attack_scores))
        for i,score in enumerate(attack_scores): results.append({"test_day":test_day,"training_days":train_days,"session_index":i,"label":"cowrie_attack","score":score,"threshold":cut,"detected":score>cut})
        for i,score in enumerate(benign_scores): results.append({"test_day":test_day,"training_days":train_days,"session_index":i,"label":"synthetic_benign","score":score,"threshold":cut,"detected":score>cut})
        results.append({"test_day":test_day,"training_days":train_days,"label":"day_summary","cowrie_sessions":len(attack_scores),"benign_test_sessions":len(benign_scores),"cowrie_detection_rate":detection,"synthetic_benign_false_positive_rate":benign_fpr,"threshold_from_validation_benign_sessions":cut,"attacker_profile_transitions":sum(profile.counts.values())})
    summary={"seed":SEED,"source":"COW160 Cowrie daily command logs; each download verifies the Zenodo license metadata","session_split":"temporal: each test day uses only earlier days for attacker-profile training","threshold":"95th percentile of separate synthetic benign validation-session attacker likelihood","benign_test":"held-out synthetic benign sessions; not real benign gateway traffic","raw_day_count":len(days),"days":names,"gateway_temporal_dataset_rows":len(temporal_rows),"gateway_training_days":names[:train_cut],"gateway_excluded_test_days":names[train_cut:],"trained_profile_privacy_checks":privacy_checks,"daily_results":[r for r in results if r["label"]=="day_summary"],"limitations":"Cowrie honeypot sessions are attacker-like, not attacks against an authenticated gateway. Synthetic benign sessions are not a real-world false-positive estimate. Token likelihood is only one profile-match signal."}
    OUT.mkdir(parents=True,exist_ok=True)
    (ROOT/"data"/"cowrie_multiday_sessions.jsonl").write_text("".join(json.dumps(row,separators=(",",":"))+"\n" for row in temporal_rows),encoding="utf-8")
    (OUT/"cowrie_multiday_raw.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    (OUT/"cowrie_multiday_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    with (OUT/"cowrie_multiday_summary.csv").open("w",newline="",encoding="utf-8") as f:
        fields=["test_day","training_days","cowrie_sessions","benign_test_sessions","cowrie_detection_rate","synthetic_benign_false_positive_rate","threshold_from_validation_benign_sessions","attacker_profile_transitions"]
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader(); w.writerows(summary["daily_results"])
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        daily=summary["daily_results"]; fig,ax=plt.subplots(figsize=(8,4)); x=range(len(daily))
        ax.plot(x,[r["cowrie_detection_rate"] for r in daily],marker="o",label="held-out Cowrie detection")
        ax.plot(x,[r["synthetic_benign_false_positive_rate"] for r in daily],marker="o",label="synthetic benign false positives")
        ax.axhline(.05,color="#666",linestyle="--",label="5% validation calibration target"); ax.set_xticks(list(x),[r["test_day"] for r in daily],rotation=30,ha="right"); ax.set(ylabel="Rate",ylim=(-.03,1.03),xlabel="Held-out day (trained on earlier days)",title="Temporal Cowrie attacker-profile holdout"); ax.grid(alpha=.25); ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(OUT/"cowrie_multiday.png",dpi=160); plt.close(fig)
    except ImportError: pass
    print(json.dumps(summary["daily_results"],indent=2))

if __name__=="__main__": main()
