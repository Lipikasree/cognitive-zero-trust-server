"""Uncertainty estimate and rate-limited step-up gate."""
from .tokenizer import CATEGORY_COST

def uncertainty(belief: float) -> float:
    return 4*belief*(1-belief)

def should_challenge(belief: float, category: str, settings: dict, last_challenge: float, now: float) -> bool:
    return (category in settings["step_up_categories"] and
            uncertainty(belief)*CATEGORY_COST.get(category,.4) >= settings["step_up_uncertainty_cost_threshold"] and
            now-last_challenge >= settings["challenge_cooldown_seconds"])
