"""
Unit Tests
Run with: pytest tests/ -v
"""

import pytest
from src.risk_scorer import calculate_risk, score_batch


# ─── Risk Scorer Tests ────────────────────────────────────────────────────────

class TestCalculateRisk:

    def test_max_score_capped_at_100(self):
        score = calculate_risk(
            source="virustotal",
            indicator_type="ip",
            tags=["malware", "ransomware", "botnet", "c2", "apt"],
            corroboration_count=10,
        )
        assert score == 100

    def test_min_score_unknown_source(self):
        score = calculate_risk(
            source="unknown_feed",
            indicator_type="ip",
            tags=[],
            corroboration_count=1,
        )
        assert score > 0

    def test_ip_scores_higher_than_hash(self):
        ip_score   = calculate_risk("virustotal", "ip")
        hash_score = calculate_risk("virustotal", "hash")
        assert ip_score > hash_score

    def test_high_risk_tags_increase_score(self):
        base  = calculate_risk("alienvault_otx", "ip", tags=[])
        tagged = calculate_risk("alienvault_otx", "ip", tags=["malware", "botnet"])
        assert tagged > base

    def test_corroboration_increases_score(self):
        single = calculate_risk("feodo_tracker", "ip", corroboration_count=1)
        multi  = calculate_risk("feodo_tracker", "ip", corroboration_count=4)
        assert multi > single

    def test_non_risk_tags_have_no_effect(self):
        base    = calculate_risk("alienvault_otx", "ip", tags=[])
        benign  = calculate_risk("alienvault_otx", "ip", tags=["scanners", "honeypot"])
        assert base == benign

    def test_virustotal_scores_higher_than_urlhaus(self):
        vt  = calculate_risk("virustotal",  "ip")
        uh  = calculate_risk("urlhaus",     "ip")
        assert vt > uh


class TestScoreBatch:

    def test_score_batch_adds_risk_score_field(self):
        docs = [
            {"indicator": "1.2.3.4", "type": "ip", "source": "feodo_tracker", "tags": ["botnet"]},
            {"indicator": "evil.com", "type": "domain", "source": "urlhaus", "tags": ["malware"]},
        ]
        result = score_batch(docs)
        for doc in result:
            assert "risk_score" in doc
            assert 0 <= doc["risk_score"] <= 100

    def test_score_batch_empty_list(self):
        assert score_batch([]) == []

    def test_score_batch_missing_fields(self):
        docs = [{"indicator": "9.9.9.9"}]
        result = score_batch(docs)
        assert "risk_score" in result[0]


# ─── Fetchers Tests (mocked) ──────────────────────────────────────────────────

class TestFetchers:

    def test_fetch_feodo_returns_list(self, requests_mock):
        requests_mock.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            json=[
                {"ip_address": "10.0.0.1", "malware": "Emotet", "country": "RU", "last_online": "2025-05-01"},
                {"ip_address": "invalid",  "malware": "Dridex",  "country": "CN", "last_online": "2025-05-01"},
            ]
        )
        from src.fetchers import fetch_feodo_tracker
        result = fetch_feodo_tracker()
        assert len(result) == 1  # invalid IP filtered out
        assert result[0]["indicator"] == "10.0.0.1"
        assert "botnet" in result[0]["tags"]

    def test_fetch_urlhaus_extracts_domain(self, requests_mock):
        requests_mock.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            json={
                "urls": [
                    {"url": "http://evil.com/payload.exe", "host": "evil.com", "tags": ["malware"], "threat": "malware_download", "url_status": "online"},
                ]
            }
        )
        from src.fetchers import fetch_urlhaus_recent
        result = fetch_urlhaus_recent()
        types = {r["type"] for r in result}
        assert "url" in types
        assert "domain" in types
