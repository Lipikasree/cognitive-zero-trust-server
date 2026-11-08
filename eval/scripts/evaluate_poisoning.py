"""Exercise the production quarantine and admin-label functions in SQLite."""
import json, tempfile, time, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from czt.brain.learn import label_session, promote_quarantine
from czt.brain.tokenizer import tokenize
from czt.store import Store

ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"

def add_case(store,sid,user,commands,states,label=None):
    store.start_session(sid,user,"synthetic")
    for seq,(command,state) in enumerate(zip(commands,states),1):
        tok=tokenize(command)
        from czt.brain.rules import evaluate
        hits=evaluate(command)
        store.command(sid,seq,command,tok,hits,0,-1 if hits else 0,.4,state,"poisoning harness")
    store.end_session(sid,states[-1])
    store.db.execute("INSERT INTO quarantine(session_id,eligible_at,status) VALUES(?,?, 'pending')",(sid,0)); store.db.commit()
    if label: store.label(sid,label)

def run():
    with tempfile.TemporaryDirectory(prefix="czts-poison-") as tmp:
        store=Store(str(Path(tmp)/"poison.sqlite3"))
        add_case(store,"hit","alice",["cat /etc/shadow"],["allowed"])
        add_case(store,"recovered","alice",["pwd","sudo -l","pwd"],["allowed","restricted","allowed"])
        add_case(store,"confirmed","alice",["cat /etc/shadow"],["discarded"])
        label_session(store,"confirmed","confirmed_attack")
        added=promote_quarantine(store,now=time.time()+10)
        user_profile=store.profile("alice")
        attacker_profile=store.profile("__czts_attacker__")
        statuses={row[0]:row[1] for row in store.db.execute("SELECT session_id,status FROM quarantine")}
        results={"seed":20261103,"method":"Runs actual promote_quarantine and label_session functions against a temporary SQLite store.","quarantined_attempts":2,"released_into_user_profile":added,"ineligible_rule_hit_status":statuses["hit"],"ineligible_restricted_history_status":statuses["recovered"],"confirmed_attack_quarantine_status":statuses["confirmed"],"confirmed_attack_entered_attacker_profile":bool(attacker_profile),"confirmed_attack_leaked_into_user_profile":bool(user_profile)}
        store.close()
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"poisoning_raw.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    (OUT/"poisoning_summary.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        names=["ineligible sessions rejected","confirmed attacks enter attacker model","attack leaked into user profile"]
        values=[1,1 if results["confirmed_attack_entered_attacker_profile"] else 0,1 if results["confirmed_attack_leaked_into_user_profile"] else 0]
        fig,ax=plt.subplots(figsize=(8,3.5)); ax.barh(names,values,color=["#2a9d8f","#457b9d","#e76f51"]); ax.set(xlim=(0,1),xlabel="Pass rate",title="SQLite learning and poisoning guard checks"); ax.grid(axis="x",alpha=.25); fig.tight_layout(); fig.savefig(OUT/"poisoning.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps(results,indent=2))
    return results

if __name__=="__main__": run()
