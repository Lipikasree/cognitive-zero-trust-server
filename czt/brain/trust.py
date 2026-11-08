"""Belief in log-odds with decay toward 0.5 and asymmetric recovery."""
import math, time

def logit(p):
    p=min(.999999,max(.000001,p)); return math.log(p/(1-p))
def sigmoid(x): return 1/(1+math.exp(-max(-30,min(30,x))))

class Trust:
    def __init__(self, belief=.97, updated=None): self.log_odds=logit(belief); self.updated=updated or time.time()
    @property
    def belief(self): return sigmoid(self.log_odds)
    def decay(self, now, half_life, recovery_factor=.25):
        dt=max(0,now-self.updated); strength=2**(-dt/max(half_life,1))
        # Time moves belief gently toward neutral; recovery after a negative command is slower.
        self.log_odds *= strength
        self.updated=now
    def add(self, evidence, recovery_factor=.25):
        self.log_odds += evidence if evidence < 0 else evidence*recovery_factor
        self.log_odds=max(-8,min(8,self.log_odds)); return self.belief
