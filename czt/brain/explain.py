"""Plain-language explanations backed by full-session counterfactual replay."""
from .trust import Trust

def replay(commands, initial_belief, initial_time, policy, settings, omit_seq=None):
    trust=Trust(initial_belief,updated=initial_time); state="allowed"
    for command in commands:
        ts=float(command["ts"])
        trust.decay(ts,settings["decay_half_life_seconds"],settings["recovery_factor"])
        if int(command["seq"])==omit_seq:
            continue
        trust.add(float(command["evidence"]),settings["recovery_factor"])
        extra=float(command.get("step_up_evidence",0.0) or 0.0)
        if extra: trust.add(extra,settings["recovery_factor"])
        state=policy.state(trust.belief,state)
    return state,trust.belief

def explain_session(commands, initial_belief, initial_time, policy, settings, actual_state):
    baseline_state,baseline_belief=replay(commands,initial_belief,initial_time,policy,settings)
    candidates=[]
    for command in reversed(commands):
        if float(command["evidence"]) >= 0 and not command.get("rule_hits"):
            continue
        counter_state,counter_belief=replay(commands,initial_belief,initial_time,policy,settings,int(command["seq"]))
        if counter_state != actual_state:
            hits=command.get("rule_hits") or []
            label=", ".join(hit["name"] for hit in hits) or command.get("raw", "command")
            candidates.append({"seq":int(command["seq"]),"command":label[:160],"counterfactual_state":counter_state,"counterfactual_belief":counter_belief,"evidence":float(command["evidence"])})
    top=candidates[:3]
    reason=f"Session replay ends {actual_state} at belief {baseline_belief:.3f}."
    if top:
        reason+=" Removing "+", ".join(f"command {x['seq']} ({x['command']})" for x in top)+" changes the replayed state."
    else:
        reason+=" Removing any single negative-evidence or rule-hit command does not change the replayed state."
    return {"reason":reason,"replay_state":baseline_state,"counterfactual_state":top[0]["counterfactual_state"] if top else baseline_state,"counterfactual_belief":top[0]["counterfactual_belief"] if top else baseline_belief,"counterfactual_flips":bool(top),"top_contributors":top}

# Backward-compatible helper used by small callers and tests.
def explain(old_state, new_state, belief, decision, hits, evidence, old_belief, policy):
    reason=("Rules: "+", ".join(h["name"] for h in hits)+". ") if hits else "Command transition was compared with this user's learned profile. "
    reason+=f"Belief is {belief:.3f}; policy decision is {decision}."
    if old_state!=new_state: reason+=f" State changed {old_state} → {new_state}."
    replay_state=policy.state(old_belief,old_state); flips=old_state!=new_state and replay_state==old_state
    return {"reason":reason,"counterfactual_state":replay_state,"counterfactual_flips":flips}
