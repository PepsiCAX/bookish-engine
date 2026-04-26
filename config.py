"""Configuration constants for XAMBooster Python."""

import os

APP_NAME = "XAMBoost VPN Panel"
APP_VERSION = "1.0.0"
DEFAULT_JSON_SOURCE_URL = "https://tiagorrg.github.io/vless-checker/keys.json"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db.sqlite")
CACHE_DIR = os.path.join(BASE_DIR, "cache")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

CACHE_TTL_SECONDS = 60
API_RATE_LIMIT = 120
LOGIN_RATE_LIMIT = 12

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-use-env-var")

DEFAULT_MANUAL_SERVERS = "\n".join([
    "vless://PLACEHOLDER_UUID@germany.example.com:443?type=tcp&security=tls#\U0001f1e9\U0001f1ea \u0413\u0435\u0440\u043c\u0430\u043d\u0438\u044f",
    "vless://PLACEHOLDER_UUID@netherlands.example.com:443?type=tcp&security=tls#\U0001f1f3\U0001f1f1 \u041d\u0438\u0434\u0435\u0440\u043b\u0430\u043d\u0434\u044b",
    "vless://PLACEHOLDER_UUID@sweden.example.com:443?type=tcp&security=tls#\U0001f1f8\U0001f1ea \u0428\u0432\u0435\u0446\u0438\u044f",
    "vless://PLACEHOLDER_UUID@poland.example.com:443?type=tcp&security=tls#\U0001f1f5\U0001f1f1 \u041f\u043e\u043b\u044c\u0448\u0430",
    "vless://PLACEHOLDER_UUID@lte.example.com:443?type=tcp&security=tls#\U0001f4f1 LTE Whitelist",
])
