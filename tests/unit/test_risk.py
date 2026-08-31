from vulnhunter.scans.risk import calculate_risk


def test_empty_findings_are_low_risk() -> None:
    assert calculate_risk([]) == (0, "LOW")


def test_score_is_bounded_to_one_hundred() -> None:
    score, level = calculate_risk(["CRITICAL"] * 20)
    assert score == 100
    assert level == "CRITICAL"
