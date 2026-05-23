"""
OSINT Feed Fetchers
Pulls threat indicators from 4 public feeds:
  1. AlienVault OTX
  2. VirusTotal (IP reputation check)
  3. Abuse.ch Feodo Tracker (C2 botnet IPs)
  4. URLhaus (malicious URLs/domains)
"""

import re
import requests
from datetime import datetime, timezone, timedelta
from rich.console import Console

from src.config import OTX_API_KEY, VT_API_KEY, ABUSE_CH_URL, URLHAUS_URL, OTX_BASE_URL

console = Console()

REQUEST_TIMEOUT = 15  # seconds


# ─── Helper ──────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_valid_ip(value: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(pattern, value):
        return False
    return all(0 <= int(p) <= 255 for p in value.split("."))


def _is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


# ─── Feed 1: AlienVault OTX ──────────────────────────────────────────────────

def fetch_otx_pulses(days_back: int = 7) -> list[dict]:
    """
    Fetch indicators from AlienVault OTX pulses modified in the last N days.
    Returns list of normalized indicator dicts.
    """
    if not OTX_API_KEY:
        console.print("[yellow]OTX_API_KEY not set — skipping AlienVault feed[/yellow]")
        return []

    since = (_now_utc() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S")
    url   = f"{OTX_BASE_URL}/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params  = {"modified_since": since, "limit": 50}

    indicators = []
    try:
        while url:
            resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", []):
                tags = [t.lower() for t in pulse.get("tags", [])]
                for ioc in pulse.get("indicators", []):
                    itype = _map_otx_type(ioc.get("type", ""))
                    value = ioc.get("indicator", "").strip()
                    if not itype or not value:
                        continue
                    indicators.append({
                        "indicator": value,
                        "type":      itype,
                        "source":    "alienvault_otx",
                        "tags":      tags,
                        "raw":       {"pulse_name": pulse.get("name", ""), "ioc_type": ioc.get("type")},
                    })

            url    = data.get("next")
            params = {}  # next URL already has params embedded

    except requests.RequestException as e:
        console.print(f"[red]OTX fetch error: {e}[/red]")

    console.print(f"[green]OTX:[/green] {len(indicators)} indicators fetched")
    return indicators


def _map_otx_type(otx_type: str) -> str | None:
    mapping = {
        "IPv4": "ip", "IPv6": "ip",
        "domain": "domain", "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
    }
    return mapping.get(otx_type)


# ─── Feed 2: VirusTotal IP Reputation ────────────────────────────────────────

def fetch_virustotal_ip(ip: str) -> dict | None:
    """
    Check a single IP against VirusTotal reputation API.
    Returns a normalized indicator dict or None if clean/error.
    """
    if not VT_API_KEY:
        console.print("[yellow]VT_API_KEY not set — skipping VirusTotal[/yellow]")
        return None

    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data  = resp.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)

        if malicious_count == 0:
            return None

        return {
            "indicator": ip,
            "type":      "ip",
            "source":    "virustotal",
            "tags":      ["malicious"],
            "raw":       {"malicious_votes": malicious_count, "stats": stats},
        }
    except requests.RequestException as e:
        console.print(f"[red]VT error for {ip}: {e}[/red]")
        return None


# ─── Feed 3: Abuse.ch Feodo Tracker (C2 Botnet IPs) ─────────────────────────

def fetch_feodo_tracker() -> list[dict]:
    """
    Fetch active C2 botnet IPs from Feodo Tracker.
    No API key required.
    """
    indicators = []
    try:
        resp = requests.get(ABUSE_CH_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        entries = resp.json()

        for entry in entries:
            ip = entry.get("ip_address", "").strip()
            if not ip or not _is_valid_ip(ip):
                continue
            indicators.append({
                "indicator": ip,
                "type":      "ip",
                "source":    "feodo_tracker",
                "tags":      ["botnet", "c2", entry.get("malware", "").lower()],
                "raw":       {
                    "country":      entry.get("country", ""),
                    "malware":      entry.get("malware", ""),
                    "last_online":  entry.get("last_online", ""),
                },
            })

    except requests.RequestException as e:
        console.print(f"[red]Feodo Tracker error: {e}[/red]")

    console.print(f"[green]Feodo:[/green] {len(indicators)} C2 IPs fetched")
    return indicators


# ─── Feed 4: URLhaus Malicious URLs ──────────────────────────────────────────

def fetch_urlhaus_recent() -> list[dict]:
    """
    Fetch recently reported malicious URLs from URLhaus.
    Extracts both the full URL and the domain as separate indicators.
    """
    indicators = []
    try:
        resp = requests.post(URLHAUS_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        for entry in data.get("urls", []):
            url_str = entry.get("url", "").strip()
            tags    = [t.lower() for t in (entry.get("tags") or [])]
            raw     = {
                "threat":     entry.get("threat", ""),
                "url_status": entry.get("url_status", ""),
            }

            if url_str:
                indicators.append({
                    "indicator": url_str,
                    "type":      "url",
                    "source":    "urlhaus",
                    "tags":      tags + ["malware"],
                    "raw":       raw,
                })

            host = entry.get("host", "").strip()
            if host and _is_valid_domain(host):
                indicators.append({
                    "indicator": host,
                    "type":      "domain",
                    "source":    "urlhaus",
                    "tags":      tags + ["malware"],
                    "raw":       raw,
                })

    except requests.RequestException as e:
        console.print(f"[red]URLhaus error: {e}[/red]")

    console.print(f"[green]URLhaus:[/green] {len(indicators)} URLs/domains fetched")
    return indicators


# ─── Master Fetch ─────────────────────────────────────────────────────────────

def fetch_all() -> list[dict]:
    """Run all fetchers and return combined deduplicated list."""
    console.print("\n[bold]Starting OSINT ingestion...[/bold]")
    all_indicators: list[dict] = []
    all_indicators += fetch_otx_pulses()
    all_indicators += fetch_feodo_tracker()
    all_indicators += fetch_urlhaus_recent()

    # Deduplicate by indicator value before returning
    seen: set[str] = set()
    unique: list[dict] = []
    for doc in all_indicators:
        key = doc["indicator"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(doc)

    console.print(f"\n[bold green]Total unique indicators:[/bold green] {len(unique)}")
    return unique
