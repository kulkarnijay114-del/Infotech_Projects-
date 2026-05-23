"""
Risk Scoring Engine
Assigns a 0–100 risk score to each threat indicator based on:
  - Source feed reliability weight
  - Indicator type weight
  - Number of malicious tags
  - Number of times seen across feeds (corroboration bonus)
"""

SOURCE_WEIGHTS: dict[str, int] = {
    "alienvault_otx": 25,
    "virustotal":     30,
    "abuse_ch":       22,
    "feodo_tracker":  18,
    "urlhaus":        15,
}

TYPE_WEIGHTS: dict[str, int] = {
    "ip":     40,
    "domain": 35,
    "hash":   25,
    "url":    30,
}

HIGH_RISK_TAGS = {
    "malware", "ransomware", "botnet", "apt", "c2",
    "phishing", "exploit", "trojan", "keylogger", "rat",
}


def calculate_risk(
    source: str,
    indicator_type: str,
    tags: list[str] | None = None,
    corroboration_count: int = 1,
) -> int:
    """
    Calculate risk score for a single indicator.

    Args:
        source: Feed that provided the indicator (e.g. 'virustotal')
        indicator_type: 'ip', 'domain', 'hash', or 'url'
        tags: List of threat category tags (e.g. ['malware', 'botnet'])
        corroboration_count: How many feeds reported this same indicator

    Returns:
        Integer risk score from 0 to 100
    """
    tags = tags or []

    source_score = SOURCE_WEIGHTS.get(source.lower(), 10)
    type_score   = TYPE_WEIGHTS.get(indicator_type.lower(), 10)

    # +5 for each high-risk tag, max +25
    tag_score = min(
        sum(5 for t in tags if t.lower() in HIGH_RISK_TAGS),
        25,
    )

    # corroboration bonus: +5 per additional feed, max +15
    corroboration_bonus = min((corroboration_count - 1) * 5, 15)

    raw = source_score + type_score + tag_score + corroboration_bonus
    return min(raw, 100)


def score_batch(indicators: list[dict]) -> list[dict]:
    """Add risk_score to each indicator dict in place and return list."""
    for doc in indicators:
        doc["risk_score"] = calculate_risk(
            source=doc.get("source", "unknown"),
            indicator_type=doc.get("type", "ip"),
            tags=doc.get("tags", []),
            corroboration_count=doc.get("corroboration_count", 1),
        )
    return indicators
