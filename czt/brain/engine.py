"""Per-command scoring, trust policy, audit explanation and safe profile updates."""
from __future__ import annotations
import json, math, time
from .tokenizer import tokenize, redact
from .rules import evaluate
from .profile import MarkovProfile, demo_priors
from .trust import Trust
from .policy import Policy
from .meta import should_challenge
from .explain import explain_session
from .totp import load_secrets, verify_and_consume

class Engine:
    def __init__(self, store, event_writer, settings, prior_path=None):
        self.store=store; self.events=event_writer; self.s=settings; self.policy=Policy(settings)
        if prior_path is None: prior_path=__import__("pathlib").Path(__file__).resolve().parents[2]/"data/generated_sessions.jsonl"
        self.role_priors,self.base_attacker_profile=demo_priors(prior_path,__import__("os").environ.get("CZTS_ATTACKER_SESSIONS"))
        self.refresh_attacker_profile()
    def refresh_attacker_profile(self):
        persisted=MarkovProfile(self.store.profile("__czts_attacker__"))
        merged=dict(self.base_attacker_profile.serialize())
        if persisted.counts:
            for key,count in persisted.serialize().items(): merged[key]=merged.get(key,0)+count
        self.attacker_profile=MarkovProfile(merged)
    async def new_session(self, username, source_ip, role="unknown"):
        import uuid
        self.refresh_attacker_profile()
        sid=str(uuid.uuid4()); self.store.start_session(sid,username,source_ip)
        self.events.write({"event_type":"session_start","session_id":sid,"username":username,"source_ip":source_ip,"state":"allowed","belief":self.s["initial_belief"]}); self.store.event({"event_type":"session_start","session_id":sid,"username":username,"source_ip":source_ip})
        return Session(self,sid,username,role)
    def event(self, event): self.events.write(event); self.store.event(event)

class Session:
    def __init__(self, engine, sid, username, role="unknown"):
        self.e=engine; self.sid=sid; self.username=username; self.role=role; self.s={**engine.s,**engine.s.get("role_overrides",{}).get(role,{})}; self.policy=Policy(self.s); self.seq=0; self.previous=[]; self.command_tokens=[]; self.state="allowed"; self.manual_restricted=False; self.trust=Trust(self.s["initial_belief"]); self.profile=MarkovProfile(engine.store.profile(username),self.s["profile_forgetting_factor"],engine.role_priors.get(role,{})); self.last_challenge=0; self.had_rule=False; self.restricted=False
        record=engine.store.get_session(sid) if hasattr(engine.store,"get_session") else None
        self.started_at=float(record["start"]) if record else self.trust.updated
    async def _read_challenge_response(self,process,limit=128):
        # Interactive relay mode is byte-oriented. Consume the line here so
        # TOTP/YES input is not sent to the target shell or audit command log.
        if getattr(process,"get_terminal_type",lambda:None)():
            response=bytearray()
            while len(response)<limit:
                char=await process.stdin.read(1)
                if not char: break
                if char in (b"\r",b"\n"):
                    self.skip_next_lf=(char==b"\r")
                    break
                if char in (b"\x08",b"\x7f"):
                    if response: response.pop()
                elif char>=b" ":
                    response.extend(char)
            return response.decode("utf-8",errors="replace")
        answer=await process.stdin.readline()
        return answer.decode(errors="replace")
    async def evaluate(self, command, process):
        self.seq+=1; s=self.s; now=time.time(); safe=redact(command); tok=tokenize(command); hits=evaluate(command)
        try:
            self.trust.decay(now,s["decay_half_life_seconds"],s["recovery_factor"])
            belief_before_command=self.trust.belief
            attacker_p=s["attacker_probability_floor"]
            profile_ev=self.profile.surprise_evidence(self.previous,tok["token"],self.e.attacker_profile,attacker_p)
            # Blend learned evidence conservatively; cap final contribution and let rules dominate.
            for hit in hits: hit["weight"]=self.e.store.rule_weight(hit["name"],hit["weight"])
            raw_evidence=profile_ev*.35 - sum(x["weight"] for x in hits)
            evidence=max(-s["max_evidence_magnitude"],min(s["max_evidence_magnitude"],raw_evidence*self.e.store.calibration_scale()))
            self.trust.add(evidence,s["recovery_factor"])
            old=self.state; self.state=self.policy.state(self.trust.belief,self.state)
            control=self.e.store.session_control(self.sid)
            if control=="restrict": self.manual_restricted=True
            elif control=="clear": self.manual_restricted=False
            elif control=="terminate": self.state="discarded"
            if self.manual_restricted and self.state!="discarded": self.state="restricted"
            if hits: self.had_rule=True
            decision=self.policy.decide(self.trust.belief,self.state,tok["category"])
            challenge_rate_limited=False; step_up_evidence=0.0
            if decision=="step_up":
                totp_required=tok["category"] in s.get("totp_categories",[])
                cooldown_ready=now-self.last_challenge>=s["challenge_cooldown_seconds"]
                challenge_ready=cooldown_ready and (totp_required or should_challenge(self.trust.belief,tok["category"],s,0,now))
                if challenge_ready:
                    self.last_challenge=now
                    if totp_required:
                        secrets=load_secrets()
                        code_ok=False
                        attempts=max(1,int(s.get("totp_attempt_limit",3)))
                        for attempt in range(attempts):
                            process.stdout.write(b"CZTS TOTP required: enter your current 6-digit authenticator code: "); await process.stdout.drain()
                            code=(await self._read_challenge_response(process)).strip()
                            if not code: break
                            if verify_and_consume(self.username,code,secrets,self.e.store):
                                code_ok=True; break
                        if code_ok:
                            step_up_evidence=.7; self.trust.add(step_up_evidence,s["recovery_factor"]); self.state=self.policy.state(self.trust.belief,self.state); decision="discard" if self.state=="discarded" else "allow"
                            self.e.event({"event_type":"step_up","session_id":self.sid,"username":self.username,"method":"totp","outcome":"confirmed","state":self.state,"belief":self.trust.belief,"reason":"TOTP verification succeeded."})
                        else:
                            step_up_evidence=-1.5; self.trust.add(step_up_evidence,s["recovery_factor"]); self.state=self.policy.state(self.trust.belief,self.state); decision="discard" if self.state=="discarded" else "block"
                            self.e.event({"event_type":"step_up","session_id":self.sid,"username":self.username,"method":"totp","outcome":"failed","state":self.state,"belief":self.trust.belief,"reason":"TOTP verification failed or the account is not enrolled."})
                    else:
                        process.stdout.write(b"CZTS inline confirmation required: type YES to confirm this ambiguous command: "); await process.stdout.drain()
                        answer=await self._read_challenge_response(process)
                    if not totp_required and answer.strip().upper()=="YES":
                        step_up_evidence=.7; self.trust.add(step_up_evidence,s["recovery_factor"]); self.state=self.policy.state(self.trust.belief,self.state); decision="discard" if self.state=="discarded" else "allow"
                        self.e.event({"event_type":"step_up","session_id":self.sid,"username":self.username,"method":"inline_confirmation","outcome":"confirmed","state":self.state,"belief":self.trust.belief,"reason":"User confirmed the ambiguous command."})
                    elif not totp_required:
                        step_up_evidence=-1.5; self.trust.add(step_up_evidence,s["recovery_factor"]); self.state=self.policy.state(self.trust.belief,self.state); decision="discard" if self.state=="discarded" else "block"
                        self.e.event({"event_type":"step_up","session_id":self.sid,"username":self.username,"method":"inline_confirmation","outcome":"failed","state":self.state,"belief":self.trust.belief,"reason":"Step-up confirmation was absent or incorrect."})
                else:
                    decision="block"; challenge_rate_limited=True
                    self.e.event({"event_type":"step_up","session_id":self.sid,"username":self.username,"method":"totp" if totp_required else "inline_confirmation","outcome":"rate_limited","state":self.state,"belief":self.trust.belief,"reason":"Sensitive command blocked because the challenge cooldown is active."})
            history=[]
            if hasattr(self.e.store,"commands"):
                for saved in self.e.store.commands(self.sid):
                    history.append({"seq":saved["seq"],"ts":saved["ts"],"raw":saved["raw"],"evidence":saved["evidence"],"step_up_evidence":saved["step_up_evidence"],"rule_hits":json.loads(saved["rule_hits"])})
            history.append({"seq":self.seq,"ts":now,"raw":safe,"evidence":evidence,"step_up_evidence":step_up_evidence,"rule_hits":hits})
            explanation=explain_session(history,s["initial_belief"],self.started_at,self.policy,s,self.state)
            reason=explanation["reason"]+f" Policy decision is {decision}."
            if challenge_rate_limited: reason+=" Step-up cooldown is active; the command was blocked."
            if control=="restrict": reason+=" An administrator manually restricted this session."
            elif control=="terminate": reason="An administrator requested termination; the session was discarded."
            peer=process.get_extra_info("peername"); source_ip=peer[0] if isinstance(peer,tuple) and peer else peer
            row={"event_type":"command","session_id":self.sid,"username":self.username,"seq":self.seq,"source_ip":source_ip,"command":safe,"token":tok["token"],"category":tok["category"],"rule_hits":hits,"rule_names":",".join(hit["name"] for hit in hits),"surprise":-profile_ev,"evidence":evidence,"belief":self.trust.belief,"state":self.state,"decision":decision,"reason":reason}
            row["counterfactual_state"]=explanation["counterfactual_state"]; row["counterfactual_belief"]=explanation["counterfactual_belief"]; row["top_contributors"]=explanation["top_contributors"]
            self.e.events.write(row); self.e.store.event(row); self.e.store.command(self.sid,self.seq,safe,tok,hits,-profile_ev,evidence,self.trust.belief,self.state,reason,step_up_evidence)
            if old!=self.state: self.e.event({"event_type":"state_change","session_id":self.sid,"username":self.username,"state":self.state,"belief":self.trust.belief,"reason":reason})
            self.previous.append(tok["token"]); self.previous=self.previous[-2:]
            self.command_tokens.append(tok["token"])
            if self.state=="restricted": self.restricted=True
            if decision=="discard": self.e.store.lock(self.username,s["discard_lock_seconds"])
            return decision,row
        except Exception as exc:
            self.state="restricted"
            import traceback
            frame=traceback.extract_tb(exc.__traceback__)[-1]
            self.e.event({"event_type":"scoring_error","session_id":self.sid,"username":self.username,"state":"restricted","reason":f"{type(exc).__name__} at {frame.name}:{frame.lineno}; fail-closed"})
            return "block",{"reason":"Scoring failed; fail-closed policy restricted this command."}
    def finish(self):
        self.e.store.end_session(self.sid,self.state)
        self.e.event({"event_type":"session_end","session_id":self.sid,"username":self.username,"state":self.state,"belief":self.trust.belief})
        # Only rule-free, unretracted allowed sessions enter delayed quarantine.
        if self.state=="allowed" and not self.had_rule and not self.restricted:
            self.e.store.db.execute("INSERT OR REPLACE INTO quarantine(session_id,eligible_at,status) VALUES(?,?, 'pending')",(self.sid,time.time()+self.s.get("quarantine_delay_seconds",300))); self.e.store.db.commit()
