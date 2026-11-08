import json, os, sqlite3, time

SCHEMA="""
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, role TEXT, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, username TEXT, source_ip TEXT, start REAL, end REAL, final_state TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS session_commands(session_id TEXT, seq INTEGER, ts REAL, raw TEXT, token TEXT, category TEXT, rule_hits TEXT, surprise REAL, evidence REAL, belief_after REAL, state_after TEXT, reason TEXT, step_up_evidence REAL NOT NULL DEFAULT 0, PRIMARY KEY(session_id,seq));
CREATE TABLE IF NOT EXISTS profiles(username TEXT PRIMARY KEY, transitions TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session_id TEXT, username TEXT, event_type TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS quarantine(session_id TEXT PRIMARY KEY, eligible_at REAL, status TEXT DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS rule_weights(name TEXT PRIMARY KEY, weight REAL NOT NULL);
CREATE TABLE IF NOT EXISTS auth_failures(username TEXT PRIMARY KEY, source_ip TEXT, window_start REAL, attempts INTEGER, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS session_controls(session_id TEXT PRIMARY KEY, action TEXT NOT NULL, requested_at REAL, requested_by TEXT DEFAULT 'admin');
CREATE TABLE IF NOT EXISTS label_outcomes(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session_id TEXT UNIQUE, prediction REAL, outcome REAL, brier REAL);
CREATE TABLE IF NOT EXISTS calibration(id INTEGER PRIMARY KEY CHECK(id=1), evidence_scale REAL NOT NULL);
CREATE TABLE IF NOT EXISTS totp_replay(username TEXT PRIMARY KEY, last_step INTEGER NOT NULL);
INSERT OR IGNORE INTO calibration(id,evidence_scale) VALUES(1,1.0);
"""
class Store:
    def __init__(self,path):
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True); self.db=sqlite3.connect(path,check_same_thread=False); self.db.row_factory=sqlite3.Row; self.db.executescript(SCHEMA)
        columns={row[1] for row in self.db.execute("PRAGMA table_info(session_commands)")}
        if "step_up_evidence" not in columns: self.db.execute("ALTER TABLE session_commands ADD COLUMN step_up_evidence REAL NOT NULL DEFAULT 0")
        self.db.commit()
    def event(self,e):
        self.db.execute("INSERT INTO events(ts,session_id,username,event_type,payload) VALUES(?,?,?,?,?)",(time.time(),e.get("session_id"),e.get("username"),e["event_type"],json.dumps(e))); self.db.commit()
    def start_session(self,sid,user,ip): self.db.execute("INSERT INTO sessions VALUES(?,?,?,?,NULL,'allowed',NULL)",(sid,user,ip,time.time())); self.db.commit()
    def command(self,sid,seq,raw,tok,hits,surprise,evidence,belief,state,reason,step_up_evidence=0.0):
        self.db.execute("INSERT INTO session_commands(session_id,seq,ts,raw,token,category,rule_hits,surprise,evidence,belief_after,state_after,reason,step_up_evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(sid,seq,time.time(),raw,tok["token"],tok["category"],json.dumps(hits),surprise,evidence,belief,state,reason,step_up_evidence)); self.db.commit()
    def end_session(self,sid,state):
        self.db.execute("UPDATE sessions SET end=?,final_state=? WHERE id=?",(time.time(),state,sid)); self.db.execute("DELETE FROM session_controls WHERE session_id=?",(sid,)); self.db.commit()
    def profile(self,user):
        r=self.db.execute("SELECT transitions FROM profiles WHERE username=?",(user,)).fetchone(); return json.loads(r[0]) if r else {}
    def save_profile(self,user,data): self.db.execute("INSERT INTO profiles VALUES(?,?) ON CONFLICT(username) DO UPDATE SET transitions=excluded.transitions",(user,json.dumps(data))); self.db.commit()
    def locked(self,user):
        r=self.db.execute("SELECT locked_until FROM users WHERE username=?",(user,)).fetchone(); return bool(r and r[0]>time.time())
    def lock(self,user,seconds): self.db.execute("INSERT INTO users(username,locked_until) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET locked_until=excluded.locked_until",(user,time.time()+seconds)); self.db.commit()
    def unlock(self,user): self.db.execute("UPDATE users SET locked_until=0 WHERE username=?",(user,)); self.db.commit()
    def sessions(self,limit=30): return self.db.execute("SELECT * FROM sessions ORDER BY start DESC LIMIT ?",(limit,)).fetchall()
    def get_session(self,sid): return self.db.execute("SELECT * FROM sessions WHERE id=?",(sid,)).fetchone()
    def commands(self,sid): return self.db.execute("SELECT * FROM session_commands WHERE session_id=? ORDER BY seq",(sid,)).fetchall()
    def label(self,sid,label): self.db.execute("UPDATE sessions SET label=? WHERE id=?",(label,sid)); self.db.commit()
    def rule_weight(self,name,default):
        r=self.db.execute("SELECT weight FROM rule_weights WHERE name=?",(name,)).fetchone(); return float(r[0]) if r else default
    def strengthen_rule(self,name,factor):
        row=self.db.execute("SELECT weight FROM rule_weights WHERE name=?",(name,)).fetchone()
        if row: value=min(5,float(row[0])*factor)
        else:
            from czt.brain.rules import RULES
            base=next((r.weight for r in RULES if r.name==name),1.0); value=min(5,base*factor)
        self.db.execute("INSERT INTO rule_weights VALUES(?,?) ON CONFLICT(name) DO UPDATE SET weight=excluded.weight",(name,value))
    def adjust_rule(self,name,factor):
        from czt.brain.rules import RULES
        base=next((r.weight for r in RULES if r.name==name),1.0); value=min(5,max(.1,self.rule_weight(name,base)*factor))
        self.db.execute("INSERT INTO rule_weights VALUES(?,?) ON CONFLICT(name) DO UPDATE SET weight=excluded.weight",(name,value)); return value
    def calibration_scale(self):
        r=self.db.execute("SELECT evidence_scale FROM calibration WHERE id=1").fetchone(); return float(r[0]) if r else 1.0
    def consume_totp_step(self,username,step):
        """Atomically accept each TOTP time step at most once per user."""
        cur=self.db.execute("INSERT INTO totp_replay(username,last_step) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET last_step=excluded.last_step WHERE totp_replay.last_step < excluded.last_step",(username,int(step)))
        accepted=cur.rowcount==1; self.db.commit(); return accepted
    def calibrate_label(self,session_id,prediction,outcome):
        import time
        brier=(prediction-outcome)**2; self.db.execute("INSERT OR REPLACE INTO label_outcomes(ts,session_id,prediction,outcome,brier) VALUES(?,?,?,?,?)",(time.time(),session_id,prediction,outcome,brier))
        rows=self.db.execute("SELECT prediction,outcome FROM label_outcomes ORDER BY id DESC LIMIT 100").fetchall(); old=self.calibration_scale(); new=old
        if len(rows)>=5 and len(rows)%5==0:
            bias=sum(r[0]-r[1] for r in rows)/len(rows)
            if bias>.10: new=max(.5,old*.9)
            elif bias<-.10: new=min(1.5,old*1.1)
            if new!=old: self.db.execute("UPDATE calibration SET evidence_scale=? WHERE id=1",(new,))
        self.db.commit(); return {"brier":brier,"scale_before":old,"scale_after":new,"labels_used":len(rows)}
    def auth_allowed(self,username,now=None):
        import time
        now=now or time.time(); r=self.db.execute("SELECT locked_until FROM auth_failures WHERE username=?",(username,)).fetchone(); return not r or float(r[0] or 0)<=now
    def record_auth_failure(self,username,source_ip,settings,now=None):
        import time
        now=now or time.time(); r=self.db.execute("SELECT source_ip,window_start,attempts,locked_until FROM auth_failures WHERE username=?",(username,)).fetchone()
        if r and now-float(r[1])<=settings["auth_window_seconds"]: start=float(r[1]); attempts=int(r[2])+1
        else: start=now; attempts=1
        locked=now+settings["auth_lock_seconds"] if attempts>=settings["auth_max_failures"] else 0
        self.db.execute("INSERT INTO auth_failures(username,source_ip,window_start,attempts,locked_until) VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET source_ip=excluded.source_ip,window_start=excluded.window_start,attempts=excluded.attempts,locked_until=excluded.locked_until",(username,source_ip,start,attempts,locked))
        self.db.commit()
        event={"event_type":"auth_failure","username":username,"source_ip":source_ip,"attempts":attempts,"locked":bool(locked)}
        self.event(event)
        return event
    def clear_auth_failures(self,username): self.db.execute("DELETE FROM auth_failures WHERE username=?",(username,)); self.db.commit()
    def request_control(self,sid,action,requested_by="admin"):
        if action=="clear": self.db.execute("DELETE FROM session_controls WHERE session_id=?",(sid,))
        else: self.db.execute("INSERT INTO session_controls(session_id,action,requested_at,requested_by) VALUES(?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET action=excluded.action,requested_at=excluded.requested_at,requested_by=excluded.requested_by",(sid,action,time.time(),requested_by))
        self.db.commit(); row=self.get_session(sid)
        self.event({"event_type":"manual_action","session_id":sid,"username":row["username"] if row else None,"action":action,"requested_by":requested_by,"reason":"Control applies when the gateway next evaluates a command."})
    def session_control(self,sid):
        row=self.db.execute("SELECT action FROM session_controls WHERE session_id=?",(sid,)).fetchone(); return row[0] if row else None
    def reconcile_sessions(self):
        import time
        rows=self.db.execute("SELECT id,username FROM sessions WHERE end IS NULL").fetchall(); events=[]; now=time.time()
        for row in rows:
            self.db.execute("UPDATE sessions SET end=?,final_state='restricted' WHERE id=?",(now,row["id"]))
            self.db.execute("DELETE FROM session_controls WHERE session_id=?",(row["id"],))
            events.append({"event_type":"session_end","session_id":row["id"],"username":row["username"],"state":"restricted","reason":"Gateway restarted or recovered an orphaned session; closed fail-safe."})
        self.db.execute("DELETE FROM session_controls WHERE session_id IN (SELECT id FROM sessions WHERE end IS NOT NULL)")
        self.db.commit()
        for event in events: self.event(event)
        return events
    def close(self): self.db.close()
