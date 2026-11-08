"""Measure gateway state-change to the local webhook in the Grafana email fan-out."""
import argparse, json, statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVENTS = ROOT / "data" / "events.jsonl"
DELIVERIES = ROOT / "data" / "alerts.jsonl"
OUT = Path(__file__).resolve().parents[1] / "results" / "alert_latency_summary.json"
LIVE = Path(__file__).resolve().parents[1] / "results" / "live_alert_sessions_raw.json"


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--state",choices=("restricted","discarded"),default="discarded"); args=parser.parse_args()
    events = [json.loads(line) for line in EVENTS.read_text(encoding="utf-8").splitlines() if line.strip()]
    deliveries = [json.loads(line) for line in DELIVERIES.read_text(encoding="utf-8").splitlines() if line.strip()]
    cohort_ids = {row["session_id"] for row in json.loads(LIVE.read_text(encoding="utf-8"))
                  if row["expected_final_state"] in ("restricted", "discarded")}
    alertname="CZTS restricted session" if args.state=="restricted" else "CZTS discarded session"
    triggers = [e for e in events if e.get("event_type") == "state_change" and e.get("state") == args.state
                and e.get("session_id") in cohort_ids]
    notices = [d for d in deliveries if d.get("status")=="firing" and any(a.get("labels", {}).get("alertname") == alertname for a in d.get("alerts", []))]
    if not triggers or not notices:
        raise SystemExit(f"Need a {args.state} state-change event and a captured firing {alertname} alert")
    pairs = []
    for notice in notices:
        notice_time = parse_time(notice["received_at"])
        notice_sessions={a.get("labels",{}).get("session_id") for a in notice.get("alerts",[])}
        if notice.get("group_labels",{}).get("session_id"):
            notice_sessions.add(notice["group_labels"]["session_id"])
        matching=[e for e in triggers if e.get("session_id") in notice_sessions and parse_time(e["timestamp"])<=notice_time]
        for trigger in matching:
            pairs.append((parse_time(trigger["timestamp"]),trigger,notice))
    if not pairs:
        raise SystemExit(f"No captured firing {alertname} follows the latest {args.state} event")
    measurements=[]
    for trigger_time,trigger,notice in pairs:
        delay=(parse_time(notice["received_at"])-trigger_time).total_seconds()
        measurements.append({"scope":"gateway event to local webhook delivery from the email fan-out; not mailbox receipt time","state":args.state,"event_timestamp":trigger["timestamp"],"session_id":trigger.get("session_id"),"webhook_received_at":notice["received_at"],"alertname":alertname,"delay_seconds":round(delay,3)})
    raw_out=OUT.with_name("alert_latency_raw.json")
    if raw_out.exists():
        old=json.loads(raw_out.read_text(encoding="utf-8"))
    elif OUT.exists():
        previous=json.loads(OUT.read_text(encoding="utf-8")); old=previous.get("measurements",[])
    else: old=[]
    combined=[item for item in old if item.get("state")!=args.state]+measurements
    state_stats={state:{"count":sum(item["state"]==state for item in combined),
                        "median_seconds":round(statistics.median([item["delay_seconds"] for item in combined if item["state"]==state]),3) if any(item["state"]==state for item in combined) else None,
                        "worst_seconds":round(max([item["delay_seconds"] for item in combined if item["state"]==state]),3) if any(item["state"]==state for item in combined) else None}
                 for state in ("restricted","discarded")}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    public_summary={"scope":"gateway event to local webhook delivery from the email fan-out; not mailbox receipt time","cohort":"latest live alert session run","seed":20261103,"states":state_stats}
    OUT.write_text(json.dumps(public_summary,indent=2)+"\n",encoding="utf-8")
    raw_out.write_text(json.dumps(combined,indent=2)+"\n",encoding="utf-8")
    with OUT.with_name("alert_latency.csv").open("w",newline="",encoding="utf-8") as f:
        import csv
        writer=csv.DictWriter(f,fieldnames=["state","event_timestamp","session_id","webhook_received_at","alertname","delay_seconds"]); writer.writeheader(); writer.writerows([{k:v for k,v in x.items() if k!="scope"} for x in combined])
    try:
        import matplotlib
        matplotlib.use("Agg"); import matplotlib.pyplot as plt
        states=[s for s in ("restricted","discarded") if state_stats[s]["median_seconds"] is not None]
        medians=[state_stats[s]["median_seconds"] for s in states]
        worst=[state_stats[s]["worst_seconds"] for s in states]
        x=list(range(len(states))); width=.34
        fig,ax=plt.subplots(figsize=(7,4)); ax.bar([i-width/2 for i in x],medians,width,label="Median",color="#4c78a8")
        ax.bar([i+width/2 for i in x],worst,width,label="Worst",color="#f28e2b")
        ax.set_xticks(list(x),states); ax.set(ylabel="Event-to-local-webhook delay (seconds)",title="Live Grafana alert delivery")
        ax.legend(frameon=False); ax.grid(axis="y",alpha=.25); fig.tight_layout(); fig.savefig(OUT.with_name("alert_latency.png"),dpi=150); plt.close(fig)
    except ImportError: pass
    print(json.dumps({"state":args.state,"count":state_stats[args.state]["count"],"median_seconds":state_stats[args.state]["median_seconds"],"worst_seconds":state_stats[args.state]["worst_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
