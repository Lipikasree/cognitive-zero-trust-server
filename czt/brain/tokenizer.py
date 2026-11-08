"""Normalize shell commands to coarse semantic tokens; never retain secret values."""
from __future__ import annotations
import re
import shlex

CATEGORY_COST = {
    "navigation": .10, "file_work": .25, "version_control": .20,
    "service_management": .45, "reconnaissance": .35,
    "privilege_escalation": .95, "credential_access": 1.0,
    "persistence": .9, "defense_evasion": .85, "exfiltration": .95,
    "destructive": 1.0, "other": .4,
}
SECRET_ARG = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)=\S+")
SECRET_FLAG = re.compile(r"(?i)(--(?:password|passwd|token|secret|api[-_]?key)(?:=|\s+)|-p)([^\s]+)")
TOKEN_FAMILIES = {
    "navigation": {"cd","pwd","ls","whoami","date","uptime"},
    "file_work": {"cat","less","more","head","tail","file","ln","mkdir","rmdir","cp","mv","touch","tar"},
    "text_search": {"grep","egrep","fgrep","find","locate","awk","nawk","sed","sort","wc","cut","expr","basename","dirname"},
    "version_control": {"git"}, "dev_tools": {"python","pytest","apt","apt-get","pip","uv"},
    "service": {"systemctl","service","journalctl"},
    "system": {"uname","hostname","id","env","df","free","ip","ss","netstat"},
    "process_control": {"ps","top","kill","nice","renice"},
    "privilege": {"sudo","su","doas","pkexec","setcap","chown","chmod","useradd","usermod","passwd","visudo"},
    "persistence": {"crontab","at","history"},
    "network": {"curl","wget","nc","ncat","socat","scp","rsync","ftp","rshd","rlogin","telnet","download","tcppost"},
    "destructive": {"rm","shred","mkfs","dd","shutdown","reboot"},
    "shell": {"sh","bash","dash","tcsh","ksh","csh","true","test","echo","printf"},
    "mail": {"sendmail","popper","mail","mailx","movemail","post"},
    "browser": {"netscape"},
    "compiler": {"gcc","cpp","cc","cc1","cfe","as","as1","ld","make","nm","ar"},
    "desktop_apps": {"xterm","dvips","mc","maple.sy","ghostvie","emacs-20","acroread","xrdb","xsetroot","4dwm","xdm","xwsh","tellwm","reaper"},
    "legacy_apps": {"generic","tcpostio","driver","launchef","mediamai","virtex","rdistd","gs","configur","java","engine","p","ugen","ld_","getopt","gettxt","gethost","getpgrp","tset","tput","unlock","endsessi","purify.s","mkpts","toolches","cgiparse","stty","lock","fifo","col","tbl","tr"},
    "printing": {"lp","lpr","lpstat","enscript"},
    "remote_admin": {"finger","rwho","who","w","last","chage","chfn","chsh"},
}
PROGRAM_FAMILY={program:family for family,programs in TOKEN_FAMILIES.items() for program in programs}
ARG_CLASSES=("no_argument","user_file","sensitive_path","external_host","system_file")
TOKEN_VOCABULARY=frozenset(f"{family}:{arg_class}" for family in TOKEN_FAMILIES for arg_class in ARG_CLASSES)|{"OTHER"}

def redact(command: str) -> str:
    command = SECRET_ARG.sub(lambda m: m.group(1) + "=[REDACTED]", command)
    command = SECRET_FLAG.sub(lambda m: m.group(1) + "[REDACTED]", command)
    return re.sub(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@", r"\1[REDACTED]@", command)[:2000]

def tokenize(command: str) -> dict:
    safe = redact(command.strip())
    try:
        parts = shlex.split(safe, posix=True)
    except ValueError:
        parts = safe.split()
    if not parts:
        return {"token": "OTHER", "category": "navigation", "cost": .1, "program": ""}
    # Keep shell operators as signal without attempting to interpret a shell grammar.
    prog = parts[0].rsplit("/", 1)[-1].lower()
    aliases = {"ll":"ls", "dir":"ls", "vi":"vim", "grep":"grep", "egrep":"grep", "fgrep":"grep"}
    prog = aliases.get(prog, prog)
    joined = safe.lower()
    category = "other"
    if prog in {"cd", "pwd", "ls", "whoami"}: category = "navigation"
    elif prog in {"git"}: category = "version_control"
    elif prog in {"systemctl", "service", "journalctl"}: category = "service_management"
    elif prog in {"cat", "less", "more", "head", "tail", "grep", "find", "locate", "ps", "id", "uname", "ip", "ss", "netstat", "env"}: category = "reconnaissance" if prog in {"ps", "id", "uname", "ip", "ss", "netstat", "env", "find"} else "file_work"
    elif prog in {"sudo", "su", "doas", "pkexec", "setcap", "chown", "chmod"}: category = "privilege_escalation"
    elif prog in {"useradd", "usermod", "passwd", "visudo"}: category = "privilege_escalation"
    elif prog in {"crontab", "at", "systemctl"} or "authorized_keys" in joined or re.search(r"/\.bashrc|/\.profile", joined): category = "persistence"
    elif prog in {"curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "ftp"}: category = "exfiltration" if prog in {"scp", "rsync", "ftp"} or any(x in joined for x in ["-x", "--data", "upload", "http", "@"] ) else "other"
    elif prog in {"rm", "shred", "mkfs", "dd", "shutdown", "reboot"}: category = "destructive"
    elif prog in {"history", "unset", "iptables", "ufw"} and any(x in joined for x in ["-c", "flush", "disable"]): category = "defense_evasion"
    elif any(x in joined for x in ["/etc/shadow", "/etc/gshadow", "id_rsa", r"\.ssh", "authorized_keys"]): category = "credential_access"
    if re.search(r"(?i)(/etc/(?:shadow|gshadow)|id_rsa|\.ssh/|authorized_keys)", safe): category = "credential_access"
    arg_class = "no_argument" if len(parts) == 1 else "user_file"
    if re.search(r"(?i)(/etc/(shadow|gshadow|sudoers)|\.ssh|authorized_keys|/root/|/var/lib/)" , safe): arg_class = "sensitive_path"
    elif re.search(r"(?i)(https?://|ftp://)", safe): arg_class = "external_host"
    elif re.search(r"(?i)(/etc/|/usr/|/boot/|/proc/|/sys/)", safe): arg_class = "system_file"
    family=PROGRAM_FAMILY.get(prog)
    token=f"{family}:{arg_class}" if family else "OTHER"
    return {"token": token, "category": category, "cost": CATEGORY_COST[category], "program": prog}
