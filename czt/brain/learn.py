"""Auditable feedback: false positives teach the user model; confirmed attacks reinforce rules."""
import json, time
import asyncio
from .profile import MarkovProfile

def _emit(store,event,event_sink=None):
    store.event(event)
    if event_sink is not None: event_sink.write(event)

def label_session(store, session_id, label, forgetting_factor=.995, event_sink=None):
    session=store.get_session(session_id)
    if not session: raise ValueError("No such session")
    store.label(session_id,label)
    commands=store.commands(session_id)
    last=commands[-1]["belief_after"] if commands else .97; prediction=max(0.0,min(1.0,float(last))); outcome=1.0 if label=="false_positive" else 0.0
    calibration=store.calibrate_label(session_id,prediction,outcome)
    if label=="false_positive":
        profile=MarkovProfile(store.profile(session["username"]),forgetting_factor); history=[]
        for row in commands:
            profile.observe(history,row["token"]); history=(history+[row["token"]])[-2:]
        store.save_profile(session["username"],profile.serialize())
        store.db.execute("UPDATE quarantine SET status='released' WHERE session_id=?",(session_id,)); store.db.commit()
        names=set()
        for row in commands:
            import json
            names.update(x["name"] for x in json.loads(row["rule_hits"]))
        for name in names: store.adjust_rule(name,.9)
        detail=f"False-positive label updated the user profile and reduced {len(names)} contributing rule weights."
        _emit(store,{"event_type":"learning_update","session_id":session_id,"username":session["username"],"update":"false_positive_profile","commands_added":len(commands),"reason":detail},event_sink)
    else:
        store.db.execute("UPDATE quarantine SET status='rejected' WHERE session_id=?",(session_id,))
        attacker=MarkovProfile(store.profile("__czts_attacker__"),forgetting_factor)
        history=[]
        for row in commands:
            attacker.observe(history,row["token"]); history=(history+[row["token"]])[-2:]
        store.save_profile("__czts_attacker__",attacker.serialize())
        names=set()
        for row in commands:
            import json
            names.update(x["name"] for x in json.loads(row["rule_hits"]))
        for name in names: store.adjust_rule(name,1.1)
        detail=f"Confirmed attack label added {len(commands)} commands to the persistent attacker profile and reinforced {len(names)} matching rules."
        _emit(store,{"event_type":"learning_update","session_id":session_id,"username":session["username"],"update":"attacker_profile","commands_added":len(commands),"reason":detail},event_sink)
    _emit(store,{"event_type":"label","session_id":session_id,"username":session["username"],"label":label,"prediction":prediction,"outcome":outcome,"brier":calibration["brier"],"evidence_scale":calibration["scale_after"],"reason":detail},event_sink)
    if calibration["scale_before"]!=calibration["scale_after"]:
        _emit(store,{"event_type":"calibration_change","session_id":session_id,"username":session["username"],**calibration,"reason":"Evidence scale adjusted from recent administrator-labeled outcomes."},event_sink)
    return detail

def promote_quarantine(store, now=None, forgetting_factor=.995, event_sink=None):
    now=now or time.time(); rows=store.db.execute("SELECT session_id FROM quarantine WHERE status='pending' AND eligible_at<=?",(now,)).fetchall(); count=0
    for item in rows:
        sid=item[0]; session=store.get_session(sid)
        commands=store.commands(sid)
        unsafe=any(row["state_after"]!="allowed" or json.loads(row["rule_hits"]) for row in commands)
        if not session or session["final_state"]!="allowed" or session["label"] or unsafe or not commands: store.db.execute("UPDATE quarantine SET status='rejected' WHERE session_id=?",(sid,)); continue
        profile=MarkovProfile(store.profile(session["username"]),forgetting_factor); history=[]
        for row in commands: profile.observe(history,row["token"]); history=(history+[row["token"]])[-2:]
        store.save_profile(session["username"],profile.serialize()); store.db.execute("UPDATE quarantine SET status='released' WHERE session_id=?",(sid,)); count+=1
        _emit(store,{"event_type":"learning_update","session_id":sid,"username":session["username"],"commands_added":len(commands),"reason":"Delayed clean-session quarantine released into profile."},event_sink)
    store.db.commit(); return count

async def quarantine_worker(store,event_sink,settings,sleep=asyncio.sleep):
    """Continuously release only mature, verified clean sessions."""
    while True:
        await sleep(max(1,int(settings.get("quarantine_poll_seconds",10))))
        try:
            promote_quarantine(store,event_sink=event_sink)
        except Exception as exc:
            event={"event_type":"learning_error","reason":type(exc).__name__+": quarantine promotion failed"}
            store.event(event); event_sink.write(event)
