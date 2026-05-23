from datetime import datetime, timezone
from pymongo import MongoClient, UpdateOne, ASCENDING, DESCENDING
from pymongo.collection import Collection
from src.config import MONGO_URI, MONGO_DB


def get_db():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def get_collection(name: str) -> Collection:
    return get_db()[name]


def setup_indexes():
    """Create all required indexes on first run."""
    indicators = get_collection("indicators")
    indicators.create_index("indicator", unique=True)
    indicators.create_index([("risk_score", DESCENDING)])
    indicators.create_index([("type", ASCENDING)])
    indicators.create_index([("blocked", ASCENDING)])
    indicators.create_index([("last_seen", DESCENDING)])

    blocked = get_collection("blocked_ips")
    blocked.create_index("ip", unique=True)

    audit = get_collection("audit_log")
    audit.create_index([("timestamp", DESCENDING)])

    print("[DB] Indexes created successfully.")


def upsert_indicators(docs: list[dict]) -> dict:
    """Bulk upsert threat indicators, deduplicating by 'indicator' field."""
    if not docs:
        return {"upserted": 0, "modified": 0}

    col = get_collection("indicators")
    now = datetime.now(timezone.utc)

    ops = []
    for doc in docs:
        doc["last_seen"] = now
        ops.append(
            UpdateOne(
                {"indicator": doc["indicator"]},
                {
                    "$set": {k: v for k, v in doc.items() if k != "first_seen"},
                    "$setOnInsert": {"first_seen": now, "blocked": False},
                },
                upsert=True,
            )
        )

    result = col.bulk_write(ops, ordered=False)
    return {
        "upserted": result.upserted_count,
        "modified": result.modified_count,
    }


def get_high_risk_ips(threshold: int = 80) -> list[dict]:
    """Return unblocked IPs above the risk threshold."""
    col = get_collection("indicators")
    return list(
        col.find(
            {"type": "ip", "risk_score": {"$gte": threshold}, "blocked": False},
            {"_id": 0, "indicator": 1, "risk_score": 1, "source": 1, "tags": 1},
        )
    )


def mark_as_blocked(ip: str):
    """Mark an indicator as blocked and log it."""
    now = datetime.now(timezone.utc)
    get_collection("indicators").update_one(
        {"indicator": ip}, {"$set": {"blocked": True, "blocked_at": now}}
    )
    get_collection("blocked_ips").update_one(
        {"ip": ip},
        {"$set": {"ip": ip, "blocked_at": now}},
        upsert=True,
    )
    _write_audit(action="BLOCK", target=ip)


def mark_as_unblocked(ip: str):
    """Mark an indicator as unblocked (rollback)."""
    now = datetime.now(timezone.utc)
    get_collection("indicators").update_one(
        {"indicator": ip}, {"$set": {"blocked": False, "unblocked_at": now}}
    )
    get_collection("blocked_ips").delete_one({"ip": ip})
    _write_audit(action="UNBLOCK", target=ip)


def get_stats() -> dict:
    """Return summary statistics for the dashboard."""
    col = get_collection("indicators")
    return {
        "total": col.count_documents({}),
        "blocked": col.count_documents({"blocked": True}),
        "high_risk": col.count_documents({"risk_score": {"$gte": 80}}),
        "ips": col.count_documents({"type": "ip"}),
        "domains": col.count_documents({"type": "domain"}),
    }


def _write_audit(action: str, target: str):
    get_collection("audit_log").insert_one(
        {
            "action": action,
            "target": target,
            "timestamp": datetime.now(timezone.utc),
        }
    )
