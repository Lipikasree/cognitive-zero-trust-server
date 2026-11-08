from datetime import datetime, timezone
import json, os, urllib.request

class EventWriter:
    def __init__(self, path, loki_url=None):
        self.path=path; self.loki_url=loki_url
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
    def write(self, event):
        event={"timestamp":datetime.now(timezone.utc).isoformat(),**event}
        line=json.dumps(event,ensure_ascii=False,separators=(",",":"))
        with open(self.path,"a",encoding="utf-8") as f: f.write(line+"\n")
        if self.loki_url:
            try:
                ts=str(int(datetime.fromisoformat(event["timestamp"].replace("Z","+00:00")).timestamp()*1e9))
                payload={"streams":[{"stream":{"app":"czts","event_type":event.get("event_type","unknown"),"state":event.get("state","unknown")},"values":[[ts,line]]}]}
                req=urllib.request.Request(self.loki_url.rstrip("/")+"/loki/api/v1/push",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
                urllib.request.urlopen(req,timeout=1).close()
            except Exception: pass
        return event
