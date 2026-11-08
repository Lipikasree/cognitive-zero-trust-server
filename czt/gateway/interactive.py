"""Prototype PTY relay which withholds Enter until the buffered line is scored."""
import asyncio
import re
import asyncssh

class AltScreenMonitor:
    """Track common terminal alternate-screen mode sequences across chunks."""
    _sequence=re.compile(rb"\x1b\[\?(?:47|1047|1049)([hl])")
    def __init__(self): self.active=False; self.tail=b""
    def feed(self,data):
        combined=self.tail+data; changes=[]
        for match in self._sequence.finditer(combined):
            active=match.group(1)==b"h"
            if active!=self.active: self.active=active; changes.append(active)
        self.tail=combined[-16:]
        return changes

async def relay_shell(process, session, upstream_config, user):
    host, port, key_path, known_hosts = upstream_config
    remote = None
    output_tasks = []
    resize_task = None
    try:
        key = asyncssh.read_private_key(key_path)
        term = process.get_terminal_type() or "xterm-256color"
        size = process.get_terminal_size()
        async with asyncssh.connect(host, port=port, username=user["upstream_username"],
                                    client_keys=[key], known_hosts=known_hosts, login_timeout=8) as conn:
            remote = await conn.create_process(term_type=term, term_size=size, encoding=None)

            screen_monitor=AltScreenMonitor()
            async def copy_stream(source, target, monitor_screen=False):
                while True:
                    data = await source.read(32768)
                    if not data: break
                    if monitor_screen:
                        for active in screen_monitor.feed(data):
                            now=asyncio.get_running_loop().time()
                            if active:
                                session.unmonitored_since=now
                                session.trust.decay(__import__("time").time(),session.s["decay_half_life_seconds"],session.s["recovery_factor"])
                                old=session.state
                                if session.state!="discarded": session.state="restricted"
                                session.restricted=True
                                session.e.event({"event_type":"unmonitored_mode_start","session_id":session.sid,"username":session.username,"state":session.state,"mode":"alternate_screen","reason":"Target entered a full-screen terminal mode; in-program keystrokes are not evaluated."})
                                if old!=session.state: session.e.event({"event_type":"state_change","session_id":session.sid,"username":session.username,"state":session.state,"belief":session.trust.belief,"reason":"Full-screen target application entered partly unmonitored mode."})
                            else:
                                started=getattr(session,"unmonitored_since",now); duration=max(0.0,now-started)
                                session.trust.decay(__import__("time").time(),session.s["decay_half_life_seconds"],session.s["recovery_factor"])
                                old=session.state; session.state=session.policy.state(session.trust.belief,session.state)
                                session.e.event({"event_type":"unmonitored_mode_end","session_id":session.sid,"username":session.username,"state":session.state,"mode":"alternate_screen","duration_seconds":round(duration,3),"reason":"Full-screen mode ended; trust decayed over the unmonitored interval."})
                                if old!=session.state: session.e.event({"event_type":"state_change","session_id":session.sid,"username":session.username,"state":session.state,"belief":session.trust.belief,"reason":"Trust policy recalculated after unmonitored full-screen activity."})
                                if session.state=="discarded":
                                    remote.terminate(); process.exit(126)
                                    return
                    target.write(data)
                    await target.drain()

            output_tasks = [asyncio.create_task(copy_stream(remote.stdout, process.stdout, True)),
                            asyncio.create_task(copy_stream(remote.stderr, process.stderr))]
            async def forward_resizes():
                previous=size
                while not remote.is_closing():
                    await asyncio.sleep(.25)
                    current=process.get_terminal_size()
                    if current and current!=previous:
                        remote.change_terminal_size(*current)
                        previous=current
            resize_task=asyncio.create_task(forward_resizes())
            line = bytearray()
            uncertain = False
            skip_lf = False
            while True:
                # Read only one byte at a time so step-up readline() cannot lose
                # bytes which were already removed from the SSH reader's buffer.
                chunk = await process.stdin.read(1)
                if not chunk: break
                forwarded = bytearray()
                for char in chunk:
                    if getattr(session,"skip_next_lf",False):
                        session.skip_next_lf=False
                        if char==10: continue
                    if skip_lf and char == 10:
                        skip_lf = False
                        continue
                    skip_lf = False
                    if char in (10, 13):
                        if char == 13: skip_lf = True
                        if forwarded:
                            remote.stdin.write(bytes(forwarded)); await remote.stdin.drain(); forwarded.clear()
                        if uncertain:
                            remote.stdin.write(b"\x15\r"); await remote.stdin.drain()
                            session.state = "restricted"; session.restricted = True
                            session.e.event({"event_type":"capture_error","session_id":session.sid,"username":session.username,"state":"restricted","reason":"Untracked terminal editing (tab completion or escape-sequence history) made the command buffer uncertain."})
                            process.stdout.write(b"\r\n[CZTS restricted] Command line editing could not be captured safely.\r\n")
                            await process.stdout.drain()
                        else:
                            command = line.decode("utf-8", errors="replace")
                            decision, event = await session.evaluate(command, process)
                            if decision == "allow":
                                remote.stdin.write(b"\r"); await remote.stdin.drain()
                            else:
                                remote.stdin.write(b"\x15\r"); await remote.stdin.drain()
                                process.stdout.write(("\r\n[CZTS %s] %s\r\n" % (decision.upper(),event.get("reason","Command blocked by policy."))).encode("utf-8",errors="replace"))
                                await process.stdout.drain()
                                if decision == "discard":
                                    remote.terminate()
                                    process.exit(126)
                                    return
                        line.clear(); uncertain = False
                    elif char in (8, 127):
                        if line: line.pop()
                        forwarded.append(char)
                    elif char == 21: # Ctrl-U: line kill
                        line.clear(); uncertain = False; forwarded.append(char)
                    elif char == 3: # Ctrl-C
                        line.clear(); uncertain = False; forwarded.append(char)
                    elif char == 9 or char == 27 or char < 32:
                        uncertain = True
                        forwarded.append(char)
                    else:
                        line.append(char); forwarded.append(char)
                if forwarded:
                    remote.stdin.write(bytes(forwarded)); await remote.stdin.drain()
            remote.stdin.write_eof()
            await remote.wait_closed()
            process.exit(remote.exit_status if remote.exit_status is not None else 0)
    except (asyncssh.Error, OSError, ValueError) as exc:
        process.stderr.write(f"CZTS upstream shell unavailable: {type(exc).__name__}\r\n".encode())
        process.exit(255)
    finally:
        if resize_task and not resize_task.done(): resize_task.cancel()
        if resize_task: await asyncio.gather(resize_task,return_exceptions=True)
        for task in output_tasks:
            if not task.done(): task.cancel()
        if output_tasks: await asyncio.gather(*output_tasks, return_exceptions=True)
