"""Measure exact command capture in the live interactive SSH gateway."""
import asyncio, json, random, sys, time
from pathlib import Path
import asyncssh
ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"; EVENTS=ROOT/"data"/"events.jsonl"; SEED=20261103

def read_events(offset):
    if not EVENTS.exists(): return []
    lines=EVENTS.read_text(encoding="utf-8",errors="replace").splitlines()
    rows=[]
    for line in lines[offset:]:
        try: rows.append(json.loads(line))
        except json.JSONDecodeError: continue
    return rows

async def connect_case(index,expected,typed,unsafe=False):
    before=len(EVENTS.read_text(encoding="utf-8",errors="replace").splitlines()) if EVENTS.exists() else 0
    key=ROOT/"keys"/"alice_client"
    async with asyncssh.connect("127.0.0.1",port=2222,username="alice",client_keys=[str(key)],known_hosts=None,login_timeout=15) as conn:
        process=await conn.create_process(term_type="xterm-256color",term_size=(80,24),encoding=None)
        output=bytearray(); done=asyncio.Event()
        async def reader():
            while True:
                data=await process.stdout.read(4096)
                if not data: break
                output.extend(data); done.set()
        task=asyncio.create_task(reader())
        await asyncio.sleep(.35)
        for value in typed:
            process.stdin.write(value); await process.stdin.drain(); await asyncio.sleep(.002)
        process.stdin.write(b"\r"); await process.stdin.drain()
        if not unsafe:
            marker=expected.split()[-1].encode()
            required=1 if b"\x7f" in b"".join(typed) else 2
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                if output.count(marker)>=required: break
                done.clear()
                try: await asyncio.wait_for(done.wait(),.2)
                except asyncio.TimeoutError: pass
        else:
            await asyncio.sleep(.35)
        # Ctrl-D on the now-empty shell prompt cleanly ends the upstream PTY
        # so the gateway writes session_end and cannot leave a live test row.
        process.stdin.write(b"\x04"); await process.stdin.drain()
        try: await asyncio.wait_for(process.wait_closed(),5)
        except asyncio.TimeoutError:
            conn.close(); await conn.wait_closed()
        task.cancel(); await asyncio.gather(task,return_exceptions=True)
    deadline=time.monotonic()+4; rows=[]
    while time.monotonic()<deadline:
        rows=read_events(before)
        starts=[r for r in rows if r.get("event_type")=="session_start"]
        if starts:
            sid=starts[0]["session_id"]
            relevant=[r for r in rows if r.get("session_id")==sid]
            if any(r.get("event_type")=="session_end" for r in relevant): return sid,relevant,bytes(output)
        await asyncio.sleep(.05)
    starts=[r for r in rows if r.get("event_type")=="session_start"]
    sid=starts[0]["session_id"] if starts else None
    return sid,[r for r in rows if r.get("session_id")==sid],bytes(output)

async def main():
    random.seed(SEED); cases=[]
    # Twenty ordinary sessions; five include a corrected character via backspace.
    for i in range(1,21):
        unique=f"CZT_CAP_{SEED}_{i:02d}"
        expected=f"echo {unique}"
        if i<=5:
            typed=f"echo {unique[:-1]}X".encode()+b"\x7f"+b"E"
            expected=f"echo {unique[:-1]}E"
        else: typed=expected.encode()
        sid,events,output=await connect_case(i,expected,[bytes([c]) for c in typed])
        commands=[r.get("command") for r in events if r.get("event_type")=="command"]
        capture_errors=[r for r in events if r.get("event_type")=="capture_error"]
        cases.append({"case":i,"kind":"ordinary_backspace" if i<=5 else "ordinary","session_id":sid,"expected_command":expected,"recorded_commands":commands,"exact_match":expected in commands,"fail_closed":bool(capture_errors),"capture_error_reasons":[r.get("reason") for r in capture_errors]})
    # Ten awkward sessions, five arrows and five tab-completion attempts. They
    # intentionally use harmless echo payloads and must be withheld by CZTS.
    for i in range(21,31):
        unique=f"CZT_UNSAFE_{SEED}_{i:02d}"; command=f"echo {unique}"
        suffix=b"\x1b[A" if i<=25 else b"\t"
        sid,events,output=await connect_case(i,command,[bytes([c]) for c in command.encode()]+[suffix],True)
        errors=[r for r in events if r.get("event_type")=="capture_error"]
        commands=[r.get("command") for r in events if r.get("event_type")=="command"]
        cases.append({"case":i,"kind":"arrow" if i<=25 else "tab","session_id":sid,"expected_command":command,"recorded_commands":commands,"exact_match":False,"fail_closed":bool(errors),"capture_error_reasons":[r.get("reason") for r in errors],"payload_was_executed":output.count(unique.encode())>=2})
    ordinary=[r for r in cases if r["kind"].startswith("ordinary")]; awkward=cases[len(ordinary):]
    summary={"seed":SEED,"interactive_sessions":len(cases),"ordinary_sessions":len(ordinary),"ordinary_commands":len(ordinary),"ordinary_exact_matches":sum(r["exact_match"] for r in ordinary),"ordinary_capture_accuracy":sum(r["exact_match"] for r in ordinary)/max(1,len(ordinary)),"ordinary_fail_closed_sessions":sum(r["fail_closed"] for r in ordinary),"ordinary_fail_closed_rate":sum(r["fail_closed"] for r in ordinary)/max(1,len(ordinary)),"awkward_sessions":len(awkward),"awkward_fail_closed_sessions":sum(r["fail_closed"] for r in awkward),"awkward_fail_closed_rate":sum(r["fail_closed"] for r in awkward)/max(1,len(awkward)),"awkward_payload_execution_count":sum(r["payload_was_executed"] for r in awkward),"cases":cases}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"capture_raw.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    (OUT/"capture_summary.json").write_text(json.dumps({k:v for k,v in summary.items() if k!="cases"},indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        labels=["Ordinary exact capture","Ordinary fail-closed","Awkward fail-closed","Awkward payload executed"]
        values=[summary["ordinary_capture_accuracy"],summary["ordinary_fail_closed_rate"],summary["awkward_fail_closed_rate"],summary["awkward_payload_execution_count"]/max(1,len(awkward))]
        fig,ax=plt.subplots(figsize=(8,4)); ax.barh(labels,values,color=["#2a9d8f","#e9c46a","#457b9d","#e76f51"]); ax.set(xlim=(0,1),xlabel="Rate",title="Interactive command capture accuracy"); ax.grid(axis="x",alpha=.25); fig.tight_layout(); fig.savefig(OUT/"capture_accuracy.png",dpi=160); plt.close(fig)
    except ImportError: pass
    print(json.dumps({k:v for k,v in summary.items() if k!="cases"},indent=2))

if __name__=="__main__": asyncio.run(main())
