"""State transitions and proportional command decisions."""
from .tokenizer import CATEGORY_COST

class Policy:
    def __init__(self, settings): self.s=settings
    def thresholds(self, belief):
        """Widen the restricted band as confidence falls toward 0.5."""
        uncertainty=4*belief*(1-belief)
        widening=self.s.get("uncertainty_band_widening",0.0)*uncertainty
        return (self.s["allowed_threshold"]+widening,
                max(0.0,self.s["discarded_threshold"]-widening))
    def state(self, belief, previous="allowed"):
        if previous == "discarded": return "discarded"
        allowed_threshold, discarded_threshold=self.thresholds(belief)
        if belief <= discarded_threshold: return "discarded"
        if previous == "allowed":
            return "allowed" if belief >= allowed_threshold else "restricted"
        recovery_threshold=min(1.0,self.s["recover_threshold"]+self.s.get("uncertainty_band_widening",0.0)*4*belief*(1-belief))
        return "allowed" if belief >= recovery_threshold else "restricted"
    def decide(self, belief, state, category):
        if state == "discarded": return "discard"
        if state == "restricted" and category in self.s["restricted_categories"]: return "block"
        if category in self.s.get("totp_categories",[]): return "step_up"
        uncertainty=4*belief*(1-belief)
        if category in self.s["step_up_categories"] and uncertainty*CATEGORY_COST.get(category,.4) >= self.s["step_up_uncertainty_cost_threshold"]:
            return "step_up"
        return "allow"
