"""Database layer: init, settings, and fetch helpers."""

import sqlite3
import os
import json
from typing import Optional, Any

from config import DB_PATH, SCHEMA_PATH, CACHE_DIR, UPLOADS_DIR, DEFAULT_MANUAL_SERVERS, DEFAULT_JSON_SOURCE_URL  # noqa: F401

_db_connection: Optional[sqlite3.Connection] = None


def _ensure_dirs() -> None:
    for d in (CACHE_DIR, UPLOADS_DIR):
        os.makedirs(d, exist_ok=True)


def get_db() -> sqlite3.Connection:
    global _db_connection
    if _db_connection is not None:
        return _db_connection

    _ensure_dirs()
    needs_init = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    if needs_init or not _tables_exist(conn):
        _init_db(conn)

    _db_connection = conn
    return conn


def get_fresh_db() -> sqlite3.Connection:
    """Return a fresh per-request connection (thread-safe)."""
    _ensure_dirs()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    if not _tables_exist(conn):
        _init_db(conn)
    return conn


def _tables_exist(conn: sqlite3.Connection) -> bool:
    for table in ("subscriptions", "plans", "settings"):
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        if cur.fetchone() is None:
            return False
    return True


def _init_db(conn: sqlite3.Connection) -> None:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    _seed_defaults(conn)


def _seed_defaults(conn: sqlite3.Connection) -> None:
    defaults = {
        "vpn_name": "XAMBoost VPN",
        "vpn_description": "Fast self-updating VPN subscription panel.",
        "logo_url": "",
        "accent_color": "#22c55e",
        "server_renames": "{}",
        "json_source_url": DEFAULT_JSON_SOURCE_URL,
        "use_manual_servers": "0",
        "manual_servers": DEFAULT_MANUAL_SERVERS,
        "response_format": "happ",
        "happ_update_interval": "5",
    }
    for key, value in defaults.items():
        if _get_setting_raw(conn, key) is None:
            _set_setting_raw(conn, key, value)
    conn.commit()


def _get_setting_raw(conn: sqlite3.Connection, key: str) -> Optional[str]:
    cur = conn.execute("SELECT value FROM settings WHERE key=? LIMIT 1", (key,))
    row = cur.fetchone()
    return row["value"] if row else None


def _set_setting_raw(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


# ---- Public API ----

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    conn = get_fresh_db()
    val = _get_setting_raw(conn, key)
    conn.close()
    return val if val is not None else default


def set_setting(key: str, value: str) -> None:
    conn = get_fresh_db()
    _set_setting_raw(conn, key, value)
    conn.commit()
    conn.close()


def set_settings(mapping: dict) -> None:
    conn = get_fresh_db()
    for k, v in mapping.items():
        _set_setting_raw(conn, str(k), str(v))
    conn.commit()
    conn.close()


def get_branding_settings() -> dict:
    return {
        "vpn_name": get_setting("vpn_name", "XAMBoost VPN") or "XAMBoost VPN",
        "vpn_description": get_setting("vpn_description", "") or "",
        "logo_url": get_setting("logo_url", "") or "",
        "accent_color": get_setting("accent_color", "#22c55e") or "#22c55e",
    }


def json_setting_array(key: str, default: Optional[list] = None) -> Any:
    if default is None:
        default = []
    raw = get_setting(key)
    if not raw or not raw.strip():
        return default
    try:
        decoded = json.loads(raw)
        return decoded if isinstance(decoded, (list, dict)) else default
    except Exception:
        return default


def app_is_installed() -> bool:
    try:
        return (
            get_setting("admin_username") is not None
            and get_setting("admin_password_hash") is not None
            and get_setting("api_token_hash") is not None
        )
    except Exception:
        return False


def fetch_subscription(sub_id: str) -> Optional[dict]:
    conn = get_fresh_db()
    cur = conn.execute(
        """SELECT s.*, p.name AS plan_name, p.duration_days AS plan_duration_days, p.price AS plan_price
           FROM subscriptions s
           LEFT JOIN plans p ON p.id = s.plan_id
           WHERE s.id = ?
           LIMIT 1""",
        (sub_id,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def fetch_plan(plan_id: str) -> Optional[dict]:
    if not plan_id or not plan_id.strip():
        return None
    conn = get_fresh_db()
    cur = conn.execute("SELECT * FROM plans WHERE id=? LIMIT 1", (plan_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def all_subscriptions() -> list:
    conn = get_fresh_db()
    cur = conn.execute(
        """SELECT s.*, p.name AS plan_name
           FROM subscriptions s
           LEFT JOIN plans p ON p.id = s.plan_id
           ORDER BY datetime(s.created_at) DESC"""
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def all_plans() -> list:
    conn = get_fresh_db()
    cur = conn.execute("SELECT * FROM plans ORDER BY duration_days ASC, name ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def collect_dashboard_stats() -> dict:
    conn = get_fresh_db()
    stats = {
        "subscriptions": conn.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0],
        "active": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status='active'").fetchone()[0],
        "expired": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE expires_at < datetime('now')").fetchone()[0],
        "plans": conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0],
    }
    conn.close()
    return stats


def initialize_database() -> None:
    conn = get_fresh_db()
    _init_db(conn)
    conn.close()
