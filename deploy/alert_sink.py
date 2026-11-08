"""Local Grafana webhook receiver for reproducible alert delivery evidence."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import os
import httpx


OUTPUT = Path(os.environ.get("CZTS_ALERTS_FILE", "/app/data/alerts.jsonl"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        state = b"discord=enabled\n" if os.environ.get("DISCORD_WEBHOOK_URL", "").strip() else b"discord=not-configured\n"
        self.wfile.write(b"ok\n" + state)

    def do_POST(self):
        if self.path not in {"/alerts", "/discord"}:
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 1_000_000:
                self.send_error(413)
                return
            payload = json.loads(self.rfile.read(size))
            if self.path == "/discord":
                webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
                if not webhook:
                    self.send_error(503, "Discord webhook is not configured")
                    return
                try:
                    response = httpx.post(webhook, json=payload, timeout=10.0)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    # Never log webhook URLs, request payloads, or response bodies.
                    print(json.dumps({"status": "discord_delivery_failed", "error": type(exc).__name__}), flush=True)
                    self.send_error(502, "Discord delivery failed")
                    return
                self.send_response(202)
                self.end_headers()
                self.wfile.write(b"forwarded\n")
                print(json.dumps({"status": "discord_delivery_accepted"}), flush=True)
                return
            summary = {
                "received_at": datetime.now(timezone.utc).isoformat(),
                "receiver": payload.get("receiver"),
                "status": payload.get("status"),
                "group_labels": payload.get("groupLabels", {}),
                "common_labels": payload.get("commonLabels", {}),
                "alerts": [
                    {"status": item.get("status"), "labels": item.get("labels", {}), "annotations": item.get("annotations", {})}
                    for item in payload.get("alerts", [])
                ],
            }
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            with OUTPUT.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(summary, separators=(",", ":")) + "\n")
            print(json.dumps({"status": summary["status"], "alerts": len(summary["alerts"])}), flush=True)
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"accepted\n")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)

    def log_message(self, format, *args):
        print("alert-sink " + format % args, flush=True)


if __name__ == "__main__":
    print("CZTS local alert sink listening on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
