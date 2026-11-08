import argparse, json, os
import sys
from pathlib import Path
from czt.store import Store
from dotenv import load_dotenv
from czt.brain.learn import label_session, promote_quarantine
from czt.events import EventWriter
ROOT=Path(__file__).resolve().parents[2]
load_dotenv(ROOT/".env")
def main():
    if hasattr(sys.stdout,"reconfigure"): sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True); sub.add_parser("sessions"); show=sub.add_parser("show"); show.add_argument("id"); label=sub.add_parser("label"); label.add_argument("id"); label.add_argument("value",choices=["false_positive","confirmed_attack"]); unlock=sub.add_parser("unlock"); unlock.add_argument("username"); reset=sub.add_parser("reset-auth"); reset.add_argument("username")
    sub.add_parser("promote")
    restrict=sub.add_parser("restrict"); restrict.add_argument("session_id")
    terminate=sub.add_parser("terminate"); terminate.add_argument("session_id")
    clear=sub.add_parser("clear-control"); clear.add_argument("session_id")
    a=p.parse_args(); st=Store(os.environ.get("CZTS_DB",str(ROOT/"data/czts.sqlite3"))); writer=EventWriter(os.environ.get("CZTS_EVENTS",str(ROOT/"data/events.jsonl")),os.environ.get("LOKI_URL"))
    if a.cmd=="sessions":
        for r in st.sessions(): print(f"{r['id']}  {r['username']}  {'LIVE' if r['end'] is None else r['final_state']}  {st.session_control(r['id']) or '-'}  {r['label'] or '-'}")
    elif a.cmd=="show":
        r=st.get_session(a.id)
        if not r: raise SystemExit("No such session")
        print(json.dumps(dict(r),indent=2));
        for c in st.commands(a.id): print(f"{c['seq']:03} {c['state_after']:10} {c['belief_after']:.3f} {c['raw']}\n    {c['reason']}")
    elif a.cmd=="label":
        print(label_session(st,a.id,a.value,event_sink=writer))
    elif a.cmd=="unlock": st.unlock(a.username); print("user unlocked")
    elif a.cmd=="promote": print(f"Released {promote_quarantine(st,event_sink=writer)} eligible clean sessions")
    elif a.cmd=="reset-auth": st.clear_auth_failures(a.username); print("failed-login counter cleared")
    elif a.cmd in {"restrict","terminate","clear-control"}:
        action={"restrict":"restrict","terminate":"terminate","clear-control":"clear"}[a.cmd]
        if not st.get_session(a.session_id): raise SystemExit("No such session")
        st.request_control(a.session_id,action); print(f"{action} requested; the gateway applies it on the next command")
if __name__=="__main__": main()
