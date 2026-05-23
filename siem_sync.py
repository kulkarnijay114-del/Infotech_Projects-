"""
SIEM Sync — MongoDB → Elasticsearch
Pipes threat indicator data into Elasticsearch so Kibana
can visualize the full threat landscape.
"""

from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch, helpers
from rich.console import Console

from src.config import ES_HOST, ES_INDEX
from src.database import get_collection

console = Console()


def get_es_client() -> Elasticsearch:
    return Elasticsearch(ES_HOST)


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "indicator":   {"type": "keyword"},
            "type":        {"type": "keyword"},
            "source":      {"type": "keyword"},
            "tags":        {"type": "keyword"},
            "risk_score":  {"type": "integer"},
            "blocked":     {"type": "boolean"},
            "first_seen":  {"type": "date"},
            "last_seen":   {"type": "date"},
            "blocked_at":  {"type": "date"},
        }
    }
}


def ensure_index(es: Elasticsearch):
    """Create the Elasticsearch index with correct mapping if it doesn't exist."""
    if not es.indices.exists(index=ES_INDEX):
        es.indices.create(index=ES_INDEX, body=INDEX_MAPPING)
        console.print(f"[green]Created ES index:[/green] {ES_INDEX}")
    else:
        console.print(f"[dim]ES index already exists:[/dim] {ES_INDEX}")


def sync_to_elasticsearch(hours_back: int = 24):
    """
    Sync indicators modified in the last N hours from MongoDB to Elasticsearch.
    Uses bulk indexing for performance.
    """
    es  = get_es_client()
    col = get_collection("indicators")

    ensure_index(es)

    since   = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    cursor  = col.find({"last_seen": {"$gte": since}})
    docs    = list(cursor)

    if not docs:
        console.print("[yellow]No new indicators to sync.[/yellow]")
        return

    def _generate_actions():
        for doc in docs:
            doc.pop("_id", None)
            doc.pop("raw", None)  # don't store raw API responses in ES
            # Convert datetime objects to ISO strings
            for field in ("first_seen", "last_seen", "blocked_at"):
                if field in doc and isinstance(doc[field], datetime):
                    doc[field] = doc[field].isoformat()
            yield {
                "_index": ES_INDEX,
                "_id":    doc["indicator"],
                "_source": doc,
            }

    success, errors = helpers.bulk(es, _generate_actions(), raise_on_error=False)
    console.print(f"[green]ES sync:[/green] {success} indexed, {len(errors)} errors")
    return success, errors


def sync_blocked_status():
    """Sync blocked=True status for recently blocked indicators."""
    es  = get_es_client()
    col = get_collection("indicators")

    blocked = list(col.find({"blocked": True}, {"_id": 0, "indicator": 1}))
    for doc in blocked:
        try:
            es.update(
                index=ES_INDEX,
                id=doc["indicator"],
                body={"doc": {"blocked": True}},
            )
        except Exception:
            pass

    console.print(f"[green]Synced blocked status for {len(blocked)} indicators[/green]")
