"""Exec-only AsyncSSH gateway. Client identities map to configured upstream identities."""
import asyncio, json, os
from pathlib import Path
import asyncssh
from dotenv import load_dotenv
from czt.store import Store
from czt.events import EventWriter
from czt.brain.engine import Engine
from czt.brain.learn import quarantine_worker
from czt.gateway.interactive import relay_shell

ROOT=Path(__file__).resolve().parents[2]
load_dotenv(ROOT/".env")
def env(name,default): return os.environ.get(name,default)
def load_settings(): return json.loads(Path(env("CZTS_SETTINGS",str(ROOT/"config/settings.json"))).read_text(encoding="utf-8"))
def load_users():
    data=json.loads(Path(env("CZTS_USERS",str(ROOT/"config/users.json"))).read_text(encoding="utf-8")); return {x["username"]:x for x in data["users"] if x.get("enabled",True)}
class Server(asyncssh.SSHServer):
    def __init__(self,users,store,settings,writer): self.users=users; self.store=store; self.settings=settings; self.writer=writer; self.username=None; self.conn=None
    def connection_made(self,conn): self.conn=conn
    def begin_auth(self,username): self.username=username; return True
    def public_key_auth_supported(self): return True
    def validate_public_key(self,username,key):
        peer=self.conn.get_extra_info("peername") if self.conn else None; source_ip=peer[0] if isinstance(peer,tuple) and peer else "unknown"
        user=self.users.get(username)
        if not user or self.store.locked(username) or not self.store.auth_allowed(username): return False
        valid=key.export_public_key().decode().strip() in [x.strip() for x in user.get("client_public_keys",[])]
        if valid: self.store.clear_auth_failures(username)
        else: self.writer.write(self.store.record_auth_failure(username,source_ip,self.settings))
        return valid
async def main():
    settings=load_settings(); users=load_users(); store=Store(env("CZTS_DB",str(ROOT/"data/czts.sqlite3"))); writer=EventWriter(env("CZTS_EVENTS",str(ROOT/"data/events.jsonl")),os.environ.get("LOKI_URL"))
    for event in store.reconcile_sessions(): writer.write(event)
    engine=Engine(store,writer,settings)
    print(f"CZTS models ready: role_profiles={len(engine.role_priors)} attacker_transitions={len(engine.attacker_profile.counts)} attacker_tokens={len(engine.attacker_profile.vocabulary)}",flush=True)
    host_key=env("CZTS_HOST_KEY",str(ROOT/"keys/gateway_host")); upstream_key_path=env("UPSTREAM_KEY",str(ROOT/"keys/upstream")); upstream_known_hosts=env("UPSTREAM_KNOWN_HOSTS",str(ROOT/"keys/upstream_known_hosts")); upstream_host=env("UPSTREAM_HOST","127.0.0.1"); upstream_port=int(env("UPSTREAM_PORT","2223"))
    if not Path(host_key).exists(): raise SystemExit(f"Missing SSH host key: {host_key}. Run scripts/generate_keys.py")
    async def process_factory(process):
        username=process.get_extra_info("username"); user=users.get(username); peer=process.get_extra_info("peername")
        if not user:
            process.stderr.write(b"Unknown user.\n"); process.exit(255); return
        session=await engine.new_session(username,str(peer[0] if peer else "unknown"),user.get("role","unknown"))
        try:
            command=process.command or ""
            if not command.strip():
                await relay_shell(process,session,(upstream_host,upstream_port,upstream_key_path,upstream_known_hosts),user)
                return
            decision,event=await session.evaluate(command,process)
            if decision=="allow":
                try:
                    key=asyncssh.read_private_key(upstream_key_path)
                    async with asyncssh.connect(upstream_host,port=upstream_port,username=user["upstream_username"],client_keys=[key],known_hosts=upstream_known_hosts,login_timeout=8) as conn:
                        result=await conn.run(command,check=False,encoding=None)
                    process.stdout.write(result.stdout or b""); process.stderr.write(result.stderr or b""); process.exit(result.exit_status if result.exit_status is not None else 0)
                except Exception as exc:
                    process.stderr.write(f"Upstream connection failed: {type(exc).__name__}\n".encode()); process.exit(255)
            else:
                process.stderr.write(f"CZTS {decision.upper()}: {event.get('reason','Command blocked by policy.')}\n".encode()); process.exit(126)
            await process.wait_closed()
        finally: session.finish()
    worker=asyncio.create_task(quarantine_worker(store,writer,settings))
    server=await asyncssh.create_server(lambda:Server(users,store,settings,writer),env("CZTS_HOST","0.0.0.0"),int(env("CZTS_PORT","2222")),server_host_keys=[host_key],process_factory=process_factory,encoding=None)
    print(f"CZTS gateway listening on {env('CZTS_HOST','0.0.0.0')}:{env('CZTS_PORT','2222')}")
    try: await asyncio.Future()
    finally:
        worker.cancel(); server.close(); await server.wait_closed()
if __name__=="__main__": asyncio.run(main())
