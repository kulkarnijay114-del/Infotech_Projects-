import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
OTX_API_KEY   = os.getenv("OTX_API_KEY", "")
VT_API_KEY    = os.getenv("VT_API_KEY", "")

# MongoDB
MONGO_URI     = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB      = os.getenv("MONGO_DB", "threat_intel")

# Elasticsearch
ES_HOST       = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX      = os.getenv("ES_INDEX", "threat_indicators")

# Enforcer
RISK_THRESHOLD  = int(os.getenv("RISK_THRESHOLD", 80))
DAEMON_INTERVAL = int(os.getenv("DAEMON_INTERVAL", 300))

# Alerts
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_EMAIL       = os.getenv("ALERT_EMAIL", "")

# OSINT Feed URLs
OTX_BASE_URL  = "https://otx.alienvault.com/api/v1"
VT_BASE_URL   = "https://www.virustotal.com/api/v3"
ABUSE_CH_URL  = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
