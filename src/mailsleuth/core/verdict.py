"""Transparent, deterministic risk assessment."""

WEIGHTS = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 4,
    "info": 0,
}

def assess(findings):
    score = min(100, sum(WEIGHTS.get(f["severity"], 0) for f in findings))
    if score >= 60:
        verdict = "HIGH_RISK"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_STRONG_INDICATORS"

    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": "limited",
        "scoring_method": "Capped sum of deterministic finding weights",
        "limitations": [
            "This is a triage score, not proof of maliciousness.",
            "Email authentication results are parsed claims, not independently verified.",
            "No attachment is executed and no URL is visited.",
        ],
    }
