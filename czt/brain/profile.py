"""Decayed, smoothed second-order user command model with lower-order backoff."""
import math
import json
from pathlib import Path
from collections import defaultdict
from .tokenizer import tokenize

class MarkovProfile:
    def __init__(self, transitions=None, decay=.995, role_prior=None):
        self.counts = {tuple(k.split("\x1f")):float(v) for k,v in (transitions or {}).items()}
        self.role_counts = {tuple(k.split("\x1f")):float(v) for k,v in (role_prior or {}).items()}
        self.decay = decay
        self.vocabulary = {key[-1] for key in self.counts}
        self.role_vocabulary = {key[-1] for key in self.role_counts}
        self.contexts, self.totals = self._index(self.counts)
        self.role_contexts, self.role_totals = self._index(self.role_counts)

    @staticmethod
    def _index(counts):
        contexts = [defaultdict(dict) for _ in range(3)]
        totals = [defaultdict(float) for _ in range(3)]
        for key, count in counts.items():
            order = len(key) - 1
            if 0 <= order <= 2:
                context, token = key[:-1], key[-1]
                contexts[order][context][token] = count
                totals[order][context] += count
        return contexts, totals

    def observe(self, history, token):
        h=list(history)
        self.vocabulary.add(token)
        for order in (0,1,2):
            if order and len(h)<order: continue
            ctx=tuple(h[-order:]) if order else ()
            key=ctx+(token,)
            old=self.counts.get(key,0)
            count=old*self.decay+1
            self.counts[key]=count
            self.contexts[order][ctx][token]=count
            self.totals[order][ctx]+=count-old
    def probability(self, history, token, floor=.01, include_role=True):
        h=list(history)
        vocab_size=len(self.vocabulary) + (0 if token in self.vocabulary else 1)
        vocab_size=max(vocab_size,2)
        models=[(self.contexts,self.totals,self.vocabulary)]+([(self.role_contexts,self.role_totals,self.role_vocabulary)] if include_role else [])
        for contexts,totals,vocabulary in models:
            vocab_size=max(len(vocabulary | {token}),2)
            for order in (2,1,0):
                if order and len(h)<order: continue
                ctx=tuple(h[-order:]) if order else ()
                rows=contexts[order].get(ctx)
                if rows:
                    return (rows.get(token,0)+.5)/(totals[order][ctx]+.5*vocab_size)
        return max(floor,1/max(len(self.vocabulary | {token}),2))
    def surprise_evidence(self, history, token, attacker_profile=None, attacker_probability=.015):
        p=max(.005,self.probability(history,token))
        a=attacker_profile.probability(history,token,include_role=False) if attacker_profile else attacker_probability
        return max(-1.2,min(1.2,math.log(p/max(a,.001))))
    def serialize(self):
        return {"\x1f".join(k):v for k,v in self.counts.items()}

def demo_priors(path, attacker_path=None):
    """Build role priors and a training-split-only attacker transition prior."""
    roles={}; attacker=MarkovProfile()
    path=Path(path)
    if not path.exists():
        from data.generate_sessions import generate
        generate(output=path)
    paths=[path]
    if attacker_path:
        external=Path(attacker_path)
        if external.exists() and external.resolve()!=path.resolve(): paths.append(external)
    for source in paths:
        for line in source.read_text(encoding="utf-8").splitlines():
            row=json.loads(line)
            if row.get("split") not in (None,"train"):
                continue
            if row.get("label")=="attack":
                model=attacker
            else:
                role=row.get("role","unknown"); model=MarkovProfile(roles.get(role,{}))
            history=[]
            for command in row.get("commands",[]):
                token=tokenize(command)["token"]
                model.observe(history,token); history=(history+[token])[-2:]
            if row.get("label")!="attack": roles[role]=model.serialize()
    return roles,attacker
