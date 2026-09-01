SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}


def calculate_risk(severities: list[str]) -> tuple[int, str]:
    """Return a bounded 0-100 score and a coarse risk level."""
    score = min(sum(SEVERITY_WEIGHTS.get(value.upper(), 1) for value in severities), 100)
    if score >= 76:
        return score, "CRITICAL"
    if score >= 51:
        return score, "HIGH"
    if score >= 26:
        return score, "MEDIUM"
    return score, "LOW"
