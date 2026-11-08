"""Verify live detection and trust-state logging for terminal alt-screen modes."""
import asyncio,json,random,sys,time
from pathlib import Path
import asyncssh
ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/"eval"/"results"; EVENTS=ROOT/"data"/"events.jsonl"; SEED=20261103

def event_rows(start):
    lines=EVENTS.read_text(encoding="utf-8",errors="replace").splitlines()
    result=[]
    for line in lines[start:]:
        try: result.append(json.loads(line))
        except json.JSONDecodeError: pass
    return result

async def main():
    random.seed(SEED); offset=len(EVENTS.read_text(encoding="utf-8",errors="replace").splitlines()) if EVENTS.exists() else 0
    command="printf '\\033[?1049h'; printf ALT_SCREEN_TEST; sleep 0.2; printf '\\033[?1049l'; echo CZT_ALT_SCREEN_DONE"
    async with asyncssh.connect("127.0.0.1",port=2222,username="alice",client_keys=[str(ROOT/"keys"/"alice_client")],known_hosts=None,login_timeout=15) as conn:
        process=await conn.create_process(term_type="xterm-256color",term_size=(80,24),encoding=None)
        output=bytearray(); wake=asyncio.Event()
        async def reader():
            while True:
                chunk=await process.stdout.read(4096)
                if not chunk: return
                output.extend(chunk); wake.set()
        reader_task=asyncio.create_task(reader()); await asyncio.sleep(.4)
        process.stdin.write(command.encode()+b"\r"); await process.stdin.drain()
        deadline=time.monotonic()+8
        while b"CZT_ALT_SCREEN_DONE" not in output and time.monotonic()<deadline:
            wake.clear()
            try: await asyncio.wait_for(wake.wait(),.25)
            except asyncio.TimeoutError: pass
        process.stdin.write(b"\x04"); await process.stdin.drain()
        try: await asyncio.wait_for(process.wait_closed(),5)
        except asyncio.TimeoutError: conn.close(); await conn.wait_closed()
        reader_task.cancel(); await asyncio.gather(reader_task,return_exceptions=True)
    deadline=time.monotonic()+4; rows=[]; sid=None
    while time.monotonic()<deadline:
        rows=event_rows(offset); starts=[r for r in rows if r.get("event_type")=="session_start"]
        if starts:
            sid=starts[0]["session_id"]; relevant=[r for r in rows if r.get("session_id")==sid]
            if any(r.get("event_type")=="session_end" for r in relevant): break
        await asyncio.sleep(.05)
    relevant=[r for r in rows if r.get("session_id")==sid]
    starts=[r for r in relevant if r.get("event_type")=="unmonitored_mode_start"]
    ends=[r for r in relevant if r.get("event_type")=="unmonitored_mode_end"]
    result={"seed":SEED,"session_id":sid,"scenario":"interactive target command emits ESC[?1049h and ESC[?1049l","marker_observed":b"CZT_ALT_SCREEN_DONE" in output,"start_event_count":len(starts),"end_event_count":len(ends),"start_state":starts[0].get("state") if starts else None,"end_state":ends[0].get("state") if ends else None,"duration_seconds":ends[0].get("duration_seconds") if ends else None,"capture_succeeded":bool(starts and ends and starts[0].get("state")=="restricted"),"events":relevant}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"alt_screen_raw.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/"alt_screen_summary.json").write_text(json.dumps({k:v for k,v in result.items() if k!="events"},indent=2)+"\n",encoding="utf-8")
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        labels=["start detected","end detected","restricted on entry"]; values=[bool(starts),bool(ends),bool(starts and starts[0].get("state")=="restricted")]
        fig,ax=plt.subplots(figsize=(7,3.5)); ax.barh(labels,[int(x) for x in values],color="#2a9d8f"); ax.set(xlim=(0,1),xlabel="Verified",title="Live alternate-screen guard check"); ax.grid(axis="x",alpha=.25); fig.tight_layout(); fig.savefig(OUT/"alt_screen.png",dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps({k:v for k,v in result.items() if k!="events"},indent=2))
    if not result["capture_succeeded"]: raise SystemExit("Alternate-screen integration check failed")

if __name__=="__main__": asyncio.run(main())
