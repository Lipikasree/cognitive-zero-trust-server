import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from czt.brain.tokenizer import tokenize,redact
from czt.brain.rules import evaluate
from czt.brain.profile import MarkovProfile
from czt.brain.trust import Trust
from czt.brain.policy import Policy
import json
import asyncio
import time

SETTINGS=json.loads((Path(__file__).resolve().parents[1]/"config/settings.json").read_text())
def test_alias_and_sensitive_categories():
    assert tokenize("dir")["program"]=="ls"
    assert tokenize("cat /etc/shadow")["category"]=="credential_access"
def test_named_rules_and_benign_lookalike():
    assert "read_shadow" in {r["name"] for r in evaluate("cat /etc/shadow")}
    assert not evaluate("cat /etc/hostname")
    assert "root_recursive_delete" in {r["name"] for r in evaluate("rm -rf /")}
def test_markov_smoothing_and_learning():
    p=MarkovProfile(); p.observe([],"pwd"); p.observe(["pwd"],"ls")
    assert 0<p.probability(["pwd"],"ls")<=1
    assert p.probability(["unseen"],"version_control:no_argument")>0
    prior=MarkovProfile(); prior.observe(["navigation:no_argument"],"navigation:user_file")
    cold=MarkovProfile(role_prior=prior.serialize())
    assert cold.probability(["navigation:no_argument"],"navigation:user_file")>cold.probability(["navigation:no_argument"],"version_control:no_argument")

def test_attacker_prior_uses_training_split_only_and_generates_missing_demo(tmp_path):
    from czt.brain.profile import demo_priors
    sessions=tmp_path/"cowrie_sessions.jsonl"
    sessions.write_text("".join(json.dumps(row)+"\n" for row in [
        {"label":"attack","split":"train","commands":["whoami"]},
        {"label":"attack","split":"test","commands":["unique-heldout-token"]},
    ]),encoding="utf-8")
    generated=tmp_path/"generated_sessions.jsonl"
    role_priors,attacker=demo_priors(generated,sessions)
    assert generated.exists() and role_priors
    assert "unique-heldout-token:no_argument" not in attacker.vocabulary
    assert "navigation:no_argument" in attacker.vocabulary
def test_trust_decay_toward_neutral_and_negative_faster():
    t=Trust(.9); before=t.log_odds; t.add(-1.0); assert t.log_odds<before
    t2=Trust(.9); t2.decay(t2.updated+1800,1800); assert abs(t2.belief-.75)<.02
def test_hysteresis():
    p=Policy(SETTINGS)
    assert p.state(.78,"allowed")=="allowed"
    assert p.state(.78,"restricted")=="restricted"
    assert p.state(.20,"restricted")=="discarded"
    assert p.state(.9,"discarded")=="discarded"

def test_counterfactual_removal_replays_the_state_change():
    from czt.brain.explain import explain
    from czt.brain.trust import logit,sigmoid
    policy=Policy({**SETTINGS,"uncertainty_band_widening":0}); prior=.72; after=sigmoid(logit(prior)-.2)
    new_state=policy.state(after,"allowed")
    result=explain("allowed",new_state,after,"allow",[],-.2,prior,policy)
    assert new_state=="restricted"
    assert result["counterfactual_state"]=="allowed"
    assert result["counterfactual_flips"] is True
def test_secret_redaction_and_step_up_uncertainty():
    assert "hunter2" not in redact("tool --password hunter2")
    from czt.brain.meta import should_challenge
    assert not should_challenge(.98,"credential_access",SETTINGS,0,500)
    assert should_challenge(.5,"credential_access",SETTINGS,0,500)

def test_delayed_quarantine_requires_elapsed_eligibility(tmp_path):
    from czt.store import Store
    from czt.brain.learn import promote_quarantine
    from czt.brain.tokenizer import tokenize
    st=Store(str(tmp_path/"test.sqlite3")); st.start_session("s1","alice","127.0.0.1")
    st.command("s1",1,"pwd",tokenize("pwd"),[],0,0,.97,"allowed","clean")
    st.end_session("s1","allowed")
    st.db.execute("INSERT INTO quarantine VALUES('s1',100,'pending')"); st.db.commit()
    assert promote_quarantine(st,now=99)==0
    assert promote_quarantine(st,now=100)==1

def test_quarantine_worker_automatically_releases_mature_clean_sessions(tmp_path):
    from czt.store import Store
    from czt.brain.learn import quarantine_worker
    from czt.brain.tokenizer import tokenize
    st=Store(str(tmp_path/"worker.sqlite3")); st.start_session("clean","alice","127.0.0.1")
    st.command("clean",1,"pwd",tokenize("pwd"),[],0,0,.97,"allowed","clean"); st.end_session("clean","allowed")
    st.db.execute("INSERT INTO quarantine(session_id,eligible_at,status) VALUES('clean',?,'pending')",(time.time()-1,)); st.db.commit()
    class StopWorker(Exception): pass
    class Writer:
        def __init__(self): self.rows=[]
        def write(self,event): self.rows.append(event)
    calls=0
    async def one_iteration(_):
        nonlocal calls
        calls+=1
        if calls>1: raise StopWorker()
    writer=Writer()
    try: asyncio.run(quarantine_worker(st,writer,{"quarantine_poll_seconds":1},one_iteration))
    except StopWorker: pass
    assert st.profile("alice")
    assert any(row.get("event_type")=="learning_update" for row in writer.rows)

def test_false_positive_label_updates_profile_and_reduces_rule_weight(tmp_path):
    from czt.store import Store
    from czt.brain.learn import label_session
    from czt.brain.tokenizer import tokenize
    st=Store(str(tmp_path/"label.sqlite3")); st.start_session("s1","alice","127.0.0.1")
    token=tokenize("cat /etc/shadow")
    st.command("s1",1,"cat /etc/shadow",token,[{"name":"read_shadow"}],1.0,-1.0,.4,"restricted","rule fired")
    st.end_session("s1","restricted")
    before=st.rule_weight("read_shadow",2.5)
    label_session(st,"s1","false_positive")
    assert st.profile("alice")
    assert st.rule_weight("read_shadow",2.5)==before*.9

def test_confirmed_attack_reinforces_matching_rule(tmp_path):
    from czt.store import Store
    from czt.brain.learn import label_session
    from czt.brain.tokenizer import tokenize
    st=Store(str(tmp_path/"attack-label.sqlite3")); st.start_session("s1","alice","127.0.0.1")
    token=tokenize("cat /etc/shadow")
    st.command("s1",1,"cat /etc/shadow",token,[{"name":"read_shadow"}],1.0,-1.0,.4,"discarded","rule fired")
    st.end_session("s1","discarded")
    before=st.rule_weight("read_shadow",2.5)
    from czt.brain.engine import Engine
    class Writer:
        def write(self,event): pass
    prior=tmp_path/"empty.jsonl"; prior.write_text("",encoding="utf-8")
    running_engine=Engine(st,Writer(),SETTINGS,prior_path=prior)
    assert tokenize("cat /etc/shadow")["token"] not in running_engine.attacker_profile.vocabulary
    label_session(st,"s1","confirmed_attack")
    assert st.rule_weight("read_shadow",2.5)==before*1.1
    new_session=asyncio.run(running_engine.new_session("alice","127.0.0.1"))
    assert tokenize("cat /etc/shadow")["token"] in running_engine.attacker_profile.vocabulary
    st.end_session(new_session.sid,"allowed")

def test_false_positive_label_changes_full_engine_replay(tmp_path):
    from czt.store import Store
    from czt.brain.engine import Engine,Session
    from czt.brain.learn import label_session
    from czt.brain.trust import Trust
    prior=tmp_path/"empty.jsonl"; prior.write_text("",encoding="utf-8")
    st=Store(str(tmp_path/"replay.sqlite3"))
    class Writer:
        def write(self,event): pass
    class Output:
        def write(self,data): pass
        async def drain(self): pass
    class Process:
        stdout=Output()
        class In:
            async def readline(self): return b"YES\n"
        stdin=In()
        def get_extra_info(self,name): return ("127.0.0.1",1234)
    engine=Engine(st,Writer(),SETTINGS,prior_path=prior)
    attacker=MarkovProfile(); attacker.observe([],"navigation:no_argument"); engine.attacker_profile=attacker
    st.start_session("before","alice","127.0.0.1")
    before=Session(engine,"before","alice"); before.trust=Trust(.90)
    first_rows=[]
    for _ in range(6):
        decision1,row1=asyncio.run(before.evaluate("sudo -l",Process())); first_rows.append(row1)
    before.finish()
    label_session(st,"before","false_positive")
    st.start_session("after","alice","127.0.0.1")
    after=Session(engine,"after","alice"); after.trust=Trust(.90); second_rows=[]
    for _ in range(6):
        decision2,row2=asyncio.run(after.evaluate("sudo -l",Process())); second_rows.append(row2)
    after.finish()
    assert second_rows[-1]["belief"] > first_rows[-1]["belief"], (first_rows[-1],second_rows[-1])
    assert second_rows[-1]["state"] != first_rows[-1]["state"] or decision2 != decision1, (decision1,first_rows[-1],decision2,second_rows[-1],st.profile("alice"))

def test_uncertainty_widens_restricted_band_and_role_overrides_step_up():
    policy=Policy({**SETTINGS,"uncertainty_band_widening":.08})
    assert policy.thresholds(.5)[0] > SETTINGS["allowed_threshold"]
    assert policy.thresholds(.5)[1] < SETTINGS["discarded_threshold"]
    role_settings={**SETTINGS,"step_up_categories":["credential_access"]}
    assert Policy(role_settings).decide(.5,"restricted","privilege_escalation")=="block"

def test_scoring_exception_fails_closed():
    from czt.brain.engine import Engine,Session
    class StoreStub:
        def profile(self,user): return {}
        def event(self,event): pass
    class Writer:
        def write(self,event): pass
    class BadProfile:
        def surprise_evidence(self,*args): raise RuntimeError("injected")
    class Process:
        class Out:
            def write(self,data): pass
            async def drain(self): pass
        stdout=Out()
    engine=Engine(StoreStub(),Writer(),SETTINGS); session=Session(engine,"s","alice"); session.profile=BadProfile()
    decision,event=asyncio.run(session.evaluate("pwd",Process()))
    assert decision=="block" and session.state=="restricted"

def test_step_up_cooldown_blocks_sensitive_command():
    from czt.brain.engine import Engine,Session
    import time
    class StoreStub:
        def profile(self,user): return {}
        def event(self,event): pass
        def command(self,*args): pass
        def rule_weight(self,name,default): return default
        def calibration_scale(self): return 1.0
        def session_control(self,sid): return None
    class Writer:
        def __init__(self): self.rows=[]
        def write(self,event): self.rows.append(event)
    class Profile:
        def surprise_evidence(self,*args): return 0
    class Output:
        def write(self,data): pass
        async def drain(self): pass
    class Process:
        stdout=Output()
        def get_extra_info(self,name): return ("127.0.0.1",1234)
    writer=Writer(); engine=Engine(StoreStub(),writer,SETTINGS); session=Session(engine,"s","alice")
    session.trust=Trust(.9); session.profile=Profile(); session.last_challenge=time.time()
    decision,_=asyncio.run(session.evaluate("cat /etc/shadow",Process()))
    assert decision=="block"
    assert any(e.get("outcome")=="rate_limited" for e in writer.rows)

def test_totp_step_up_allows_high_cost_command_and_records_outcome(monkeypatch):
    from czt.brain.engine import Engine,Session
    import pyotp
    secret=pyotp.random_base32()
    monkeypatch.setattr("czt.brain.engine.load_secrets",lambda:{"alice":secret})
    class StoreStub:
        def profile(self,user): return {}
        def event(self,event): pass
        def command(self,*args): pass
        def rule_weight(self,name,default): return default
        def calibration_scale(self): return 1.0
        def session_control(self,sid): return None
        def consume_totp_step(self,username,step): return True
    class Writer:
        def __init__(self): self.rows=[]
        def write(self,event): self.rows.append(event)
    class Output:
        def write(self,data): pass
        async def drain(self): pass
    class Input:
        def __init__(self): self.code=pyotp.TOTP(secret).now(); self.data=bytearray((self.code+"\r").encode())
        async def read(self,count):
            result=bytes(self.data[:count]); del self.data[:count]; return result
    class Process:
        stdout=Output()
        def __init__(self): self.stdin=Input()
        def get_terminal_type(self): return "xterm-256color"
        def get_extra_info(self,name): return ("127.0.0.1",1234)
    writer=Writer(); session=Session(Engine(StoreStub(),writer,SETTINGS),"s","alice")
    session.profile=type("P",(),{"surprise_evidence":lambda *args:0.0})()
    process=Process()
    decision,row=asyncio.run(session.evaluate("rm /tmp/demo-file",process))
    assert decision=="allow"
    assert any(e.get("event_type")=="step_up" and e.get("method")=="totp" and e.get("outcome")=="confirmed" for e in writer.rows)
    assert secret not in json.dumps(writer.rows)
    assert process.stdin.code not in json.dumps(writer.rows)
    assert session.skip_next_lf is True
    assert row["counterfactual_state"]=="allowed"

def test_full_session_counterfactual_removes_cited_command():
    from czt.brain.explain import explain_session
    from czt.brain.trust import Trust
    from czt.brain.policy import Policy
    policy=Policy({**SETTINGS,"uncertainty_band_widening":0})
    trust=Trust(.72,updated=1000); trust.decay(1001,SETTINGS["decay_half_life_seconds"],SETTINGS["recovery_factor"]); trust.add(-.2,SETTINGS["recovery_factor"])
    actual=policy.state(trust.belief,"allowed")
    explanation=explain_session([{"seq":1,"ts":1001,"raw":"sudo -l","evidence":-.2,"step_up_evidence":0,"rule_hits":[{"name":"sudo_enumeration"}]}],.72,1000,policy,SETTINGS,actual)
    assert actual=="restricted"
    assert explanation["counterfactual_flips"] is True
    assert explanation["counterfactual_state"]=="allowed"

def test_alternate_screen_detection_across_stream_chunks():
    from czt.gateway.interactive import AltScreenMonitor
    monitor=AltScreenMonitor()
    assert monitor.feed(b"output\x1b[?10")==[]
    assert monitor.feed(b"49hscreen")==[True]
    assert monitor.feed(b"screen\x1b[?1049l")==[False]

def test_failed_authentication_window_and_lockout(tmp_path):
    from czt.store import Store
    st=Store(str(tmp_path/"auth.sqlite3")); cfg={"auth_max_failures":5,"auth_window_seconds":60,"auth_lock_seconds":90}
    for i in range(4): assert st.record_auth_failure("alice","127.0.0.1",cfg,now=100+i)
    assert st.record_auth_failure("alice","127.0.0.1",cfg,now=104)["locked"] is True
    assert st.auth_allowed("alice",now=105) is False
    assert st.auth_allowed("alice",now=195) is True
    st.clear_auth_failures("alice"); assert st.auth_allowed("alice",now=105) is True

def test_feedback_brier_and_bounded_evidence_calibration(tmp_path):
    from czt.store import Store
    st=Store(str(tmp_path/"calibration.sqlite3"))
    for i in range(5): outcome=st.calibrate_label(f"attack-{i}",.8,0)
    assert abs(outcome["brier"]-.64)<1e-9 and outcome["scale_after"]==.9
    for i in range(5): outcome=st.calibrate_label(f"benign-{i}",.2,1)
    assert abs(outcome["scale_after"]-.9)<1e-9
    for i in range(5): outcome=st.calibrate_label(f"benign-more-{i}",.2,1)
    assert abs(outcome["scale_after"]-.99)<1e-9
    base=st.rule_weight("read_shadow",2.5)
    assert st.adjust_rule("read_shadow",.9)==base*.9
    assert st.adjust_rule("read_shadow",1.1)==base*.99

def test_admin_session_controls_are_persisted(tmp_path):
    from czt.store import Store
    st=Store(str(tmp_path/"control.sqlite3")); st.start_session("s1","alice","127.0.0.1")
    st.request_control("s1","restrict"); assert st.session_control("s1")=="restrict"
    st.request_control("s1","terminate"); assert st.session_control("s1")=="terminate"
    st.request_control("s1","clear"); assert st.session_control("s1") is None
    st.request_control("s1","restrict"); st.end_session("s1","restricted"); assert st.session_control("s1") is None

def test_orphaned_sessions_reconcile_fail_closed(tmp_path):
    from czt.store import Store
    st=Store(str(tmp_path/"reconcile.sqlite3")); st.start_session("s1","alice","127.0.0.1")
    events=st.reconcile_sessions(); row=st.get_session("s1")
    assert row["end"] is not None and row["final_state"]=="restricted"
    assert events[0]["event_type"]=="session_end"

def test_manual_restriction_blocks_risky_command():
    from czt.brain.engine import Engine,Session
    class StoreStub:
        def profile(self,user): return {}
        def event(self,event): pass
        def command(self,*args): pass
        def rule_weight(self,name,default): return default
        def calibration_scale(self): return 1.0
        def session_control(self,sid): return "restrict"
    class Writer:
        def write(self,event): pass
    class Output:
        def write(self,data): pass
        async def drain(self): pass
    class Process:
        stdout=Output()
        def get_extra_info(self,name): return ("127.0.0.1",1234)
    session=Session(Engine(StoreStub(),Writer(),SETTINGS),"s","alice")
    decision,event=asyncio.run(session.evaluate("rm -rf /",Process()))
    assert decision=="block" and session.state=="restricted"
    assert "administrator manually restricted" in event["reason"]

def test_manual_termination_discards_and_locks_user():
    from czt.brain.engine import Engine,Session
    class StoreStub:
        locked_user=None
        def profile(self,user): return {}
        def event(self,event): pass
        def command(self,*args): pass
        def rule_weight(self,name,default): return default
        def calibration_scale(self): return 1.0
        def session_control(self,sid): return "terminate"
        def lock(self,user,seconds): self.locked_user=user
    class Writer:
        def write(self,event): pass
    class Output:
        def write(self,data): pass
        async def drain(self): pass
    class Process:
        stdout=Output()
        def get_extra_info(self,name): return ("127.0.0.1",1234)
    store=StoreStub(); session=Session(Engine(store,Writer(),SETTINGS),"s","alice")
    decision,event=asyncio.run(session.evaluate("pwd",Process()))
    assert decision=="discard" and session.state=="discarded" and store.locked_user=="alice"
    assert "administrator requested termination" in event["reason"]
