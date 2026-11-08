"""Transparent, explainable command rules. Patterns are intentionally conservative."""
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: str
    weight: float
    rationale: str
    @property
    def severity(self):
        return "critical" if self.weight>=2.5 else "high" if self.weight>=1.8 else "medium"

RULES = [
    Rule("read_shadow", "credential_access", r"(?:cat|less|head|grep|awk|sed)\b[^\n]*\s/etc/(?:shadow|gshadow)\b", 2.5, "Reads the local password hash database."),
    Rule("ssh_material", "credential_access", r"\b(?:cat|less|cp|tar|grep)\b[^\n]*(?:\.ssh/(?:id_|authorized_keys)|authorized_keys)", 1.8, "Accesses SSH credentials or trust configuration."),
    Rule("sudo_enumeration", "privilege_escalation", r"\bsudo\s+-l\b", .65, "Enumerates delegated privilege; may be legitimate administration."),
    Rule("account_admin", "privilege_escalation", r"\b(?:useradd|usermod)\b[^\n]*(?:-aG?\s*(?:sudo|wheel)|sudo|wheel)", 2.0, "Changes privileged account membership."),
    Rule("persistence_cron", "persistence", r"\b(?:crontab\s+-e|echo\b[^\n]*>>?\s*/etc/cron|tee\s+/etc/cron)", 1.8, "Creates or edits scheduled persistence."),
    Rule("persistence_keys", "persistence", r"(?:>>?\s*[^\n]*authorized_keys|tee\s+[^\n]*authorized_keys)", 2.0, "Adds a persistent SSH access key."),
    Rule("history_clear", "defense_evasion", r"\b(?:history\s+-c|shred\s+[^\n]*\.bash_history|rm\s+[^\n]*\.bash_history)", 1.6, "Removes shell command history."),
    Rule("remote_fetch", "exfiltration", r"\b(?:curl|wget)\b[^\n]*(?:https?://|ftp://)", 1.0, "Fetches content from an external host."),
    Rule("reverse_shell", "exfiltration", r"\b(?:nc|ncat|socat)\b[^\n]*(?:-e\s*/(?:bin|usr/bin)/(?:ba)?sh|/dev/tcp/)", 2.8, "Constructs a shell over a network connection."),
    Rule("encoded_network", "exfiltration", r"base64\b[^\n]*\|[^\n]*(?:curl|nc|wget)", 2.5, "Pipes encoded data to a network utility."),
    Rule("root_recursive_delete", "destructive", r"\brm\s+-[^\n]*r[^\n]*f[^\n]*\s/(?:\s|$)", 3.0, "Attempts recursive forced deletion from filesystem root."),
    Rule("shadow_copy", "destructive", r"\b(?:lvremove|wipefs|mkfs|dd\s+if=)[^\n]*", 1.8, "Can overwrite or destroy filesystem data."),
]

def evaluate(command: str) -> list[dict]:
    hits=[]
    for r in RULES:
        if re.search(r.pattern, command, re.I):
            hits.append({"name":r.name,"category":r.category,"severity":r.severity,"weight":r.weight,"reason":r.rationale})
    return hits
