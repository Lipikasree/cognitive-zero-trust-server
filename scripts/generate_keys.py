from pathlib import Path
import json, os, subprocess
import asyncssh

root=Path(__file__).resolve().parents[1]; d=root/"keys"; d.mkdir(exist_ok=True)
for name in ("gateway_host","upstream","alice_client","target_host"):
    path=d/name
    if not path.exists(): path.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    pub=path.with_name(path.name+".pub")
    if not pub.exists():
        key=asyncssh.read_private_key(path); pub.write_bytes(key.export_public_key())
    if os.name=="nt":
        identity=subprocess.check_output(["whoami"],text=True).strip()
        subprocess.run(["icacls",str(path),"/inheritance:r","/grant:r",f"{identity}:(F)","SYSTEM:(F)"],check=True,capture_output=True)
users=root/"config/users.json"
data=json.loads(users.read_text(encoding="utf-8")); data["users"][0]["client_public_keys"]=[(d/"alice_client.pub").read_text(encoding="utf-8").strip()]; data["users"][0]["upstream_public_key"]=(d/"upstream.pub").read_text(encoding="utf-8").strip()
users.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
(d/"upstream_known_hosts").write_text("[127.0.0.1]:2223 "+(d/"target_host.pub").read_text(encoding="utf-8").strip()+"\ntarget "+(d/"target_host.pub").read_text(encoding="utf-8").strip()+"\n",encoding="utf-8")
(d/"totp_secrets.json").touch(exist_ok=True)
if not (d/"totp_secrets.json").read_text(encoding="utf-8").strip(): (d/"totp_secrets.json").write_text("{}\n",encoding="utf-8")
if os.name=="nt":
    identity=subprocess.check_output(["whoami"],text=True).strip()
    subprocess.run(["icacls",str(d/"totp_secrets.json"),"/inheritance:r","/grant:r",f"{identity}:(F)","SYSTEM:(F)"],check=True,capture_output=True)
(d/".gitkeep").touch(exist_ok=True)
print(f"Keys written to {d}")
print("Demo public keys have been written to config/users.json; upstream.pub is mounted into the demo target.")
print("The demo target host key is pinned in keys/upstream_known_hosts.")
