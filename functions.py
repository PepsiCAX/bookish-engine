"""VPN logic: URI parsing, singbox config, subscription payload building, rate limiting."""

import base64
import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote, unquote

import urllib.request
from config import CACHE_DIR, CACHE_TTL_SECONDS, APP_NAME, APP_VERSION, DEFAULT_JSON_SOURCE_URL
from models import (
    get_setting,
    json_setting_array,
)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_timestamp() -> int:
    return int(time.time())


def uuid_v4() -> str:
    return str(uuid.uuid4())


def subscription_public_id() -> str:
    return uuid_v4().replace("-", "")


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value if value else "item"


def normalize_accent_color(value: str) -> str:
    value = value.strip()
    return value if re.match(r"^#[0-9a-fA-F]{6}$", value) else "#22c55e"


def parse_datetime_to_utc(value: Optional[str]) -> Optional[str]:
    if not value or not value.strip():
        return None
    value = value.strip()
    # Handle datetime-local format (no seconds)
    if "T" in value and len(value) == 16:
        value = value + ":00"
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return None


def next_expiry_from_days(current_expires_at: Optional[str], days: int) -> str:
    if current_expires_at:
        try:
            base = datetime.strptime(current_expires_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if base.timestamp() > time.time():
                return (base + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def ensure_dirs() -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Rate limiting (file-based)
# ---------------------------------------------------------------------------

def rate_limit(scope: str, limit: int, window_seconds: int = 60) -> bool:
    ensure_dirs()
    ip = _current_ip()
    bucket = int(time.time() // window_seconds)
    path = os.path.join(
        CACHE_DIR,
        "ratelimit_" + hashlib.sha1(f"{scope}|{ip}|{bucket}".encode()).hexdigest() + ".json",
    )
    count = 0
    if os.path.exists(path):
        try:
            data = json.loads(open(path).read())
            count = int(data.get("count", 0))
        except Exception:
            count = 0
    count += 1
    try:
        with open(path, "w") as f:
            json.dump({"count": count, "updated_at": now_utc()}, f)
    except Exception:
        pass
    return count <= limit


def _current_ip() -> str:
    # Will be set by Flask context at call site via g or request
    try:
        from flask import request as flask_request
        return flask_request.remote_addr or "cli"
    except Exception:
        return "cli"


# ---------------------------------------------------------------------------
# URI Parsing
# ---------------------------------------------------------------------------

def parse_proxy_uri(uri: str) -> Optional[dict]:
    if not uri:
        return None
    try:
        parts = urlparse(uri)
    except Exception:
        return None

    if not parts.scheme:
        return None

    scheme = parts.scheme.lower()

    if scheme in ("vless", "trojan"):
        query: dict = {}
        if parts.query:
            for k, vlist in parse_qs(parts.query, keep_blank_values=True).items():
                query[k] = vlist[0] if vlist else ""
        fragment = unquote(parts.fragment) if parts.fragment else ""
        return {
            "scheme": scheme,
            "raw": uri,
            "user": parts.username or "",
            "password": parts.password or "",
            "host": parts.hostname or "",
            "port": parts.port,
            "query": query,
            "name": fragment.strip(),
        }

    if scheme == "ss":
        fragment = ""
        if "#" in uri:
            uri_no_frag, frag_part = uri.split("#", 1)
            fragment = unquote(frag_part)
        else:
            uri_no_frag = uri
        body = uri_no_frag[len("ss://"):]
        # Try base64 decode first
        try:
            decoded = base64.b64decode(
                body.replace("-", "+").replace("_", "/") + "==", validate=False
            ).decode("utf-8", errors="replace")
            if "@" in decoded:
                left, right = decoded.split("@", 1)
            else:
                raise ValueError("no @")
        except Exception:
            if "@" in body:
                left, right = body.split("@", 1)
            else:
                return None
        method_password = left.split(":", 1)
        method = method_password[0] if method_password else ""
        password = method_password[1] if len(method_password) > 1 else ""
        host_port = right.split(":", 1)
        host = host_port[0] if host_port else ""
        port = int(host_port[1]) if len(host_port) > 1 and host_port[1].isdigit() else 0
        return {
            "scheme": "ss",
            "raw": uri,
            "method": method,
            "password": password,
            "host": host,
            "port": port,
            "name": fragment.strip(),
            "query": {},
        }

    return None


def extract_server_uris(value, collector: Optional[dict] = None) -> list:
    if collector is None:
        collector = {}
    schemes = ("vless://", "vmess://", "trojan://", "ss://")
    if isinstance(value, str):
        trimmed = value.strip()
        for s in schemes:
            if trimmed.lower().startswith(s):
                collector[trimmed] = trimmed
                break
    elif isinstance(value, (list, tuple)):
        for item in value:
            extract_server_uris(item, collector)
    elif isinstance(value, dict):
        for item in value.values():
            extract_server_uris(item, collector)
    return list(collector.values())


def clean_server_label(label: str) -> str:
    label = re.sub(r"\s+", " ", label.strip())
    return label if label else "VPN Server"


def server_rename_for(candidates: list, mapping: dict) -> Optional[str]:
    for candidate in candidates:
        candidate = str(candidate).strip()
        if candidate and candidate in mapping and str(mapping[candidate]).strip():
            return str(mapping[candidate]).strip()
    return None


def rebuild_uri_with_label(uri: str, label: str) -> str:
    base = uri.split("#")[0]
    return base + "#" + quote(label, safe="")


def is_whitelist_label(label: str) -> bool:
    return bool(re.search(r"CIDR|Whitelist", label, re.IGNORECASE))


def is_pseudo_country(country: str) -> bool:
    # Baltics is now allowed — not treated as pseudo
    return country.strip().lower() in ("other",)


def strip_server_badges(label: str) -> str:
    label = unquote(label)
    label = re.sub(r"^\p{So}+\s*", "", label) if False else re.sub(r"^[\U00010000-\U0010ffff]+\s*", "", label)
    label = re.sub(r"\|\s*\[[^\]]+\]", "", label)
    label = re.sub(r"\[[^\]]*CIDR[^\]]*\]", "Whitelist", label, flags=re.IGNORECASE)
    label = re.sub(r"\b(BL|YA|VK)\b", "", label)
    label = re.sub(r"\s*\|\s*", " | ", label)
    label = re.sub(r"\s+", " ", label)
    label = label.strip(" \t\n\r\x0b|-")
    return label if label else "VPN Server"


def normalize_country_name(country: str) -> str:
    country = country.strip()
    country = re.sub(r"\s*Whitelist\s*$", "", country, flags=re.IGNORECASE)
    if country.lower() == "the netherlands":
        return "Netherlands"
    return country


def country_to_flag_emoji(country: str) -> str:
    flag_map = {
        "Russia": "RU", "Finland": "FI", "Netherlands": "NL", "Germany": "DE",
        "United States": "US", "United Kingdom": "GB", "Sweden": "SE", "France": "FR",
        "Poland": "PL", "Spain": "ES", "Italy": "IT", "Canada": "CA",
        "Baltics": "LV",
    }
    norm = normalize_country_name(country)
    iso = flag_map.get(norm)
    if not iso:
        return ""
    # Regional indicator symbols
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso.upper())


def country_to_russian_name(country: str) -> str:
    ru_map = {
        "Russia": "Россия", "Finland": "Финляндия", "Netherlands": "Нидерланды",
        "Germany": "Германия", "United States": "США", "United Kingdom": "Великобритания",
        "Sweden": "Швеция", "France": "Франция", "Poland": "Польша",
        "Spain": "Испания", "Italy": "Италия", "Canada": "Канада",
        "Baltics": "Прибалтика",
    }
    norm = normalize_country_name(country)
    return ru_map.get(norm, norm)


def enhance_label_for_happ(country: str, label: str) -> str:
    flag = country_to_flag_emoji(country)
    rus = country_to_russian_name(country)
    parts = []
    if flag:
        parts.append(flag)
    if rus:
        parts.append(rus)
    if parts:
        return " ".join(parts) + " — " + label
    return label


def infer_country_from_label(label: str) -> str:
    # Remove emoji and special chars, keep letters/numbers/spaces/dashes
    normalized = re.sub(r"[^\w\s,\-]", "", label, flags=re.UNICODE).strip()
    if not normalized:
        return "Unknown"
    parts = normalized.split(",")
    first = parts[0].strip()
    if first:
        return first
    words = normalized.split()
    return " ".join(words[:min(2, len(words))]) or "Unknown"


def humanize_source_key(key: str) -> str:
    key = re.sub(r"^w_", "", key)
    key = key.replace("_", " ")
    return key.title()


# ---------------------------------------------------------------------------
# sing-box transport and TLS builders
# ---------------------------------------------------------------------------

def singbox_transport_from_query(query: dict) -> Optional[dict]:
    ttype = query.get("type", "tcp").lower()
    if not ttype or ttype == "tcp":
        return None
    if ttype == "ws":
        transport: dict = {"type": "ws"}
        if query.get("path"):
            transport["path"] = query["path"]
        host = query.get("host", "")
        if not host and query.get("sni"):
            host = query["sni"]
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if ttype == "grpc":
        transport = {"type": "grpc"}
        if query.get("serviceName"):
            transport["service_name"] = query["serviceName"]
        if query.get("mode"):
            transport["mode"] = query["mode"]
        return transport
    if ttype == "httpupgrade":
        return {
            "type": "httpupgrade",
            "host": query.get("host", ""),
            "path": query.get("path", "/"),
        }
    if ttype == "xhttp":
        t: dict = {"type": "http", "path": query.get("path", "/")}
        host = query.get("host", "")
        if host:
            t["host"] = [host]
        return t
    return {"type": ttype}


def singbox_tls_from_query(query: dict, host: str) -> Optional[dict]:
    security = query.get("security", "none").lower()
    if security not in ("tls", "reality"):
        return None
    tls: dict = {
        "enabled": True,
        "server_name": query.get("sni", host),
    }
    if query.get("insecure", "0") not in ("0", ""):
        tls["insecure"] = True
    if query.get("alpn"):
        tls["alpn"] = [a.strip() for a in query["alpn"].split(",") if a.strip()]
    if query.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
    if security == "reality" and query.get("pbk"):
        reality: dict = {"enabled": True, "public_key": query["pbk"]}
        if query.get("sid"):
            reality["short_id"] = query["sid"]
        tls["reality"] = reality
    return tls


def singbox_outbound_from_server(parsed: dict, index: int, rename_map: dict) -> Optional[dict]:
    raw_name = parsed.get("name", "")
    name = clean_server_label(raw_name or f"{parsed.get('host','server')}:{parsed.get('port','')}")
    renamed = server_rename_for(
        [parsed.get("name", ""), parsed.get("host", ""), parsed.get("raw", "")],
        rename_map,
    )
    display_name = renamed if renamed else name
    tag = slugify(display_name) + f"-{index}"

    scheme = parsed.get("scheme", "")

    if scheme == "vless":
        outbound: dict = {
            "type": "vless",
            "tag": tag,
            "server": parsed.get("host", ""),
            "server_port": int(parsed.get("port") or 443),
            "uuid": parsed.get("user", ""),
        }
        if parsed.get("query", {}).get("flow"):
            outbound["flow"] = parsed["query"]["flow"]
        tls = singbox_tls_from_query(parsed.get("query", {}), parsed.get("host", ""))
        if tls:
            outbound["tls"] = tls
        transport = singbox_transport_from_query(parsed.get("query", {}))
        if transport:
            outbound["transport"] = transport
        if parsed.get("query", {}).get("packetEncoding"):
            outbound["packet_encoding"] = parsed["query"]["packetEncoding"]
        return {
            "tag": tag,
            "display_name": display_name,
            "country": infer_country_from_label(display_name),
            "outbound": outbound,
        }

    if scheme == "trojan":
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": parsed.get("host", ""),
            "server_port": int(parsed.get("port") or 443),
            "password": parsed.get("user", ""),
        }
        tls = singbox_tls_from_query(parsed.get("query", {}), parsed.get("host", ""))
        if tls:
            outbound["tls"] = tls
        transport = singbox_transport_from_query(parsed.get("query", {}))
        if transport:
            outbound["transport"] = transport
        return {
            "tag": tag,
            "display_name": display_name,
            "country": infer_country_from_label(display_name),
            "outbound": outbound,
        }

    if scheme == "ss":
        outbound = {
            "type": "shadowsocks",
            "tag": tag,
            "server": parsed.get("host", ""),
            "server_port": int(parsed.get("port") or 443),
            "method": parsed.get("method", ""),
            "password": parsed.get("password", ""),
        }
        return {
            "tag": tag,
            "display_name": display_name,
            "country": infer_country_from_label(display_name),
            "outbound": outbound,
        }

    return None


# ---------------------------------------------------------------------------
# Remote JSON source fetch (with cache)
# ---------------------------------------------------------------------------

def fetch_remote_json_source() -> dict:
    """Fetch the remote JSON source with file-based cache (CACHE_TTL_SECONDS)."""
    ensure_dirs()
    url = get_setting("json_source_url", DEFAULT_JSON_SOURCE_URL) or DEFAULT_JSON_SOURCE_URL
    cache_key = hashlib.sha1(url.encode()).hexdigest()
    cache_path = os.path.join(CACHE_DIR, f"source_{cache_key}.json")
    meta_path = os.path.join(CACHE_DIR, f"source_{cache_key}.meta.json")
    now = int(time.time())

    cached_raw = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                cached_raw = f.read()
        except Exception:
            cached_raw = None

    fetched_at = 0
    if os.path.exists(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as f:
                meta = json.loads(f.read())
            fetched_at = int(meta.get("fetched_at", 0))
        except Exception:
            fetched_at = 0

    if cached_raw is not None and (now - fetched_at) < CACHE_TTL_SECONDS:
        decoded = json.loads(cached_raw)
        return {"url": url, "raw": cached_raw, "decoded": decoded, "cached": True, "stale": False, "fetched_at": fetched_at}

    raw = _download_url(url)
    if raw is not None:
        decoded = json.loads(raw)
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(raw)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({"fetched_at": now, "url": url}, f)
        except Exception:
            pass
        return {"url": url, "raw": raw, "decoded": decoded, "cached": False, "stale": False, "fetched_at": now}

    if cached_raw is not None:
        decoded = json.loads(cached_raw)
        return {"url": url, "raw": cached_raw, "decoded": decoded, "cached": True, "stale": True, "fetched_at": fetched_at}

    raise RuntimeError("Unable to fetch the remote source and no cache is available.")


def _download_url(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": f"{APP_NAME}/{APP_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if 200 <= resp.status < 300:
                return resp.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# curated_subscription_servers (mirrors PHP logic exactly)
# ---------------------------------------------------------------------------

def extract_candidates_from_bucket(bucket: dict, country: str, is_whitelist: bool, bucket_key: str) -> list:
    candidates = []

    def _make_candidate(uri: str, latency: float) -> Optional[dict]:
        parsed = parse_proxy_uri(uri)
        if parsed is None:
            return None
        raw_label = str(parsed.get("name") or "")
        resolved_country = normalize_country_name(country)
        if is_pseudo_country(resolved_country):
            resolved_country = normalize_country_name(infer_country_from_label(strip_server_badges(raw_label)))
        is_cidr = bool(re.search(r"CIDR", raw_label, re.IGNORECASE))
        is_white = is_whitelist or is_whitelist_label(raw_label) or bucket_key.startswith("w_")
        final_label = (resolved_country + " Whitelist") if is_white else resolved_country
        return {
            "uri": rebuild_uri_with_label(uri, final_label),
            "raw_uri": uri,
            "latency_ms": latency,
            "host": str(parsed.get("host") or ""),
            "port": int(parsed.get("port") or 0),
            "country": resolved_country,
            "label": final_label,
            "is_whitelist": is_white,
            "is_cidr": is_cidr,
            "bucket": bucket_key,
        }

    # Try best first
    if bucket.get("best") and isinstance(bucket["best"], str):
        cand = _make_candidate(bucket["best"], 0.0)
        if cand is not None:
            candidates.append(cand)

    # Fallback: top10 (sorted by latency)
    if not candidates:
        top10 = bucket.get("top10", [])
        if isinstance(top10, list):
            for entry in top10:
                if not isinstance(entry, dict) or not entry.get("key"):
                    continue
                cand = _make_candidate(str(entry["key"]), float(entry.get("latency_ms", 999999)))
                if cand is not None:
                    candidates.append(cand)

    return candidates


# Countries we want to keep from the remote source (normalized names).
_ALLOWED_COUNTRIES = {"Germany", "Netherlands", "Sweden", "Poland", "Baltics"}


def _normalize_to_allowed(country: str) -> Optional[str]:
    """Return the canonical allowed-country name if this country matches, else None."""
    c = normalize_country_name(country).strip()
    for allowed in _ALLOWED_COUNTRIES:
        if c.lower() == allowed.lower():
            return allowed
    return None


def curated_subscription_servers(source: dict) -> dict:
    """Fetch best server for each of the 4 allowed countries + 1 LTE whitelist server."""
    ordinary_by_country: dict = {}   # country -> best candidate
    whitelist_candidates: list = []

    for key, value in source.items():
        if not isinstance(value, dict) or key == "updated_at":
            continue
        if key == "other_countries":
            for sub_country, sub_bucket in value.items():
                if not isinstance(sub_bucket, dict):
                    continue
                canonical = _normalize_to_allowed(str(sub_country))
                if canonical is None:
                    continue
                for cand in extract_candidates_from_bucket(sub_bucket, str(sub_country), False, str(sub_country)):
                    if cand["is_whitelist"]:
                        continue
                    existing = ordinary_by_country.get(canonical)
                    if existing is None or cand["latency_ms"] < existing["latency_ms"]:
                        cand["country"] = canonical
                        ordinary_by_country[canonical] = cand
            continue

        is_whitelist_bucket = key.startswith("w_")
        raw_country = humanize_source_key(key)

        if is_whitelist_bucket:
            for cand in extract_candidates_from_bucket(value, raw_country, True, key):
                whitelist_candidates.append(cand)
        else:
            canonical = _normalize_to_allowed(raw_country)
            if canonical is None:
                continue
            for cand in extract_candidates_from_bucket(value, raw_country, False, key):
                if cand["is_whitelist"]:
                    continue
                existing = ordinary_by_country.get(canonical)
                if existing is None or cand["latency_ms"] < existing["latency_ms"]:
                    cand["country"] = canonical
                    ordinary_by_country[canonical] = cand

    # Keep order: DE, NL, SE, PL, Baltics — relabel with flag + Russian name
    order = ["Germany", "Netherlands", "Sweden", "Poland", "Baltics"]
    ordinary = []
    for c in order:
        if c not in ordinary_by_country:
            continue
        cand = ordinary_by_country[c]
        flag = country_to_flag_emoji(c)
        rus = country_to_russian_name(c)
        new_label = (flag + " " + rus).strip()
        cand["label"] = new_label
        cand["uri"] = rebuild_uri_with_label(cand["raw_uri"], new_label)
        ordinary.append(cand)

    # Pick exactly 1 whitelist server, relabel as LTE
    whitelist_candidates.sort(key=lambda x: (not x["is_cidr"], x["latency_ms"]))
    picked_whitelist = []
    if whitelist_candidates:
        cand = whitelist_candidates[0]
        cand["label"] = "📱 LTE Белый список"
        cand["uri"] = rebuild_uri_with_label(cand["raw_uri"], "📱 LTE Белый список")
        picked_whitelist = [cand]

    all_servers = ordinary + picked_whitelist
    countries = [s["country"] for s in ordinary]
    return {
        "ordinary": ordinary,
        "whitelist": picked_whitelist,
        "all": all_servers,
        "uris": [s["uri"] for s in all_servers],
        "countries": countries,
    }


def collect_countries_from_source(source: dict) -> list:
    countries: dict = {}
    for key, value in source.items():
        if key == "updated_at":
            continue
        if key == "other_countries" and isinstance(value, dict):
            for c in value:
                if isinstance(value[c], dict):
                    countries[c] = c
            continue
        if key == "w_other":
            continue
        if isinstance(value, dict) and ("best" in value or "top10" in value):
            countries[humanize_source_key(key)] = humanize_source_key(key)
    for uri in extract_server_uris(source):
        parsed = parse_proxy_uri(uri)
        if parsed and parsed.get("name"):
            c = infer_country_from_label(str(parsed["name"]))
            countries[c] = c
    return sorted(countries.keys())


# ---------------------------------------------------------------------------
# Subscription payload (supports both remote and manual modes)
# ---------------------------------------------------------------------------

def build_happ_profile_header(subscription: dict, payload: Optional[dict] = None) -> str:
    if payload is None:
        payload = {}
    title = get_setting("vpn_name", subscription.get("name", "Subscription")) or subscription.get("name", "Subscription")
    update_interval = int(get_setting("happ_update_interval", "5") or "5")
    support = str(subscription.get("telegram_id", "") or "")
    if support and not support.startswith("http"):
        if support.startswith("@"):
            support = "https://t.me/" + support.lstrip("@")
        else:
            support = "https://t.me/" + support
    instruction_link = _absolute_url("subscription/" + (subscription.get("id") or ""))
    announce = str(subscription.get("description") or "")
    announce_b64 = base64.b64encode(announce.encode("utf-8")).decode() if announce else ""
    expires_unix = 0
    if subscription.get("expires_at"):
        try:
            dt = datetime.strptime(str(subscription["expires_at"]), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            expires_unix = int(dt.timestamp())
        except Exception:
            pass
    created = subscription.get("created_at", now_utc())
    count = len(payload.get("servers", [])) if isinstance(payload.get("servers"), list) else 0
    lines = [
        f"# profile-title: {title}",
        f"# profile-update-interval: {update_interval}",
        f"# support-url: {support}",
        f"# profile-web-page-url: {instruction_link}",
        f"# announce: base64:{announce_b64}",
        f"# subscription-userinfo: upload=0; download=0; total=0; expire={expires_unix}",
        "# traffic-limit: 0",
        f"# Date/Time: {created}",
        f"# Количество: {count}",
    ]
    return "\n".join(lines) + "\n"


def _absolute_url(path: str = "") -> str:
    """Best-effort absolute URL; falls back to relative when not in request context."""
    try:
        from flask import request as flask_request
        base = flask_request.host_url.rstrip("/")
        return base + "/" + path.lstrip("/")
    except Exception:
        return "/" + path.lstrip("/")


def build_default_subscription_payload(subscription: dict, source: Optional[dict] = None) -> dict:
    """Build the default payload. Uses manual servers or remote source depending on settings."""
    # Always use remote source if provided; fallback to manual only if explicitly set
    use_manual = (get_setting("use_manual_servers", "0") or "0") == "1"

    if use_manual:
        # Manual servers fallback
        manual_raw = get_setting("manual_servers", "") or ""
        lines = [l.strip() for l in re.split(r"\r?\n", manual_raw) if l.strip()]
        manual_items = []
        for line in lines:
            parsed = parse_proxy_uri(line)
            if parsed is None:
                continue
            label = parsed.get("name", "")
            country = infer_country_from_label(label) if label else "Unknown"
            enhanced = enhance_label_for_happ(country, label or line)
            manual_items.append({
                "uri": rebuild_uri_with_label(line, enhanced),
                "raw_uri": line,
                "latency_ms": 999999.0,
                "host": parsed.get("host", ""),
                "port": int(parsed.get("port") or 0),
                "country": country,
                "label": enhanced,
                "is_whitelist": False,
                "is_cidr": False,
                "bucket": "manual",
            })
        ordinary = manual_items
        whitelist: list = []
    else:
        # Remote JSON source — filtered to DE/NL/SE/PL + 1 LTE whitelist
        if source is None:
            raise RuntimeError("Remote source not loaded.")
        curated = curated_subscription_servers(source)
        ordinary = curated["ordinary"]
        whitelist = curated["whitelist"]
        manual_items = curated["all"]

    return {
        "meta": {
            **_build_subscription_meta(subscription),
            "server_count": len(manual_items),
            "stable_country_count": len(ordinary),
            "whitelist_server_count": len(whitelist),
        },
        "servers": [i["uri"] for i in manual_items],
        "server_groups": {
            "standard": [
                {"country": i["country"], "name": i["label"], "latency_ms": i["latency_ms"], "uri": i["uri"]}
                for i in ordinary
            ],
            "whitelist": [],
        },
        "routing": {
            "rules": [
                {"type": "field", "geoip": ["ru"], "outbound": "direct"},
                {"type": "field", "outbound": "proxy"},
            ]
        },
    }


def _build_subscription_meta(subscription: dict) -> dict:
    return {
        "name": subscription.get("name"),
        "description": subscription.get("description"),
        "badge": subscription.get("badge"),
        "expires_at": subscription.get("expires_at"),
        "telegram_id": subscription.get("telegram_id"),
        "plan": subscription.get("plan_name"),
        "subscription_id": subscription.get("id"),
        "vpn_name": get_setting("vpn_name", "XAMBoost VPN"),
        "logo_url": get_setting("logo_url", ""),
        "accent_color": get_setting("accent_color", "#22c55e"),
    }


def build_happ_config(source: Optional[dict] = None) -> dict:
    """Build sing-box config. Uses manual servers or remote source depending on settings."""
    rename_map = json_setting_array("server_renames", {})
    if not isinstance(rename_map, dict):
        rename_map = {}

    use_manual = (get_setting("use_manual_servers", "0") or "0") == "1"

    if use_manual:
        manual_raw = get_setting("manual_servers", "") or ""
        uris = [l.strip() for l in re.split(r"\r?\n", manual_raw) if l.strip()]
        ordinary_count = len(uris)
        whitelist_count = 0
    else:
        if source is None:
            raise RuntimeError("Remote source not loaded.")
        curated = curated_subscription_servers(source)
        uris = curated["uris"]
        ordinary_count = len(curated["ordinary"])
        whitelist_count = len(curated["whitelist"])

    converted = []
    tags = []
    countries: dict = {}

    for idx, uri in enumerate(uris):
        parsed = parse_proxy_uri(uri)
        if parsed is None:
            continue
        result = singbox_outbound_from_server(parsed, idx + 1, rename_map)
        if result is None:
            continue
        converted.append(result["outbound"])
        tags.append(result["tag"])
        countries[result["country"]] = result["country"]

    if not tags:
        raise RuntimeError("No compatible proxy servers found.")

    converted.append({"type": "selector", "tag": "proxy", "outbounds": tags, "default": tags[0]})
    converted.append({"type": "direct", "tag": "direct"})

    return {
        "config": {
            "log": {"level": "info"},
            "outbounds": converted,
            "route": {
                "rules": [
                    {"geoip": ["ru"], "outbound": "direct"},
                    {"outbound": "proxy"},
                ]
            },
        },
        "countries": sorted(countries.keys()),
        "server_count": len(tags),
        "ordinary_count": ordinary_count,
        "whitelist_count": whitelist_count,
    }


def subscription_status_detail(subscription: dict) -> dict:
    if subscription.get("status", "active") != "active":
        return {"ok": False, "code": 403, "reason": "Subscription is disabled."}
    expires_at = subscription.get("expires_at", "")
    if expires_at:
        try:
            dt = datetime.strptime(str(expires_at), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if dt.timestamp() < time.time():
                return {"ok": False, "code": 410, "reason": "Subscription has expired."}
        except Exception:
            return {"ok": False, "code": 410, "reason": "Subscription has expired."}
    return {"ok": True, "code": 200, "reason": "active"}


def collect_countries_from_manual() -> list:
    manual_raw = get_setting("manual_servers", "") or ""
    lines = [l.strip() for l in re.split(r"\r?\n", manual_raw) if l.strip()]
    countries = set()
    for line in lines:
        parsed = parse_proxy_uri(line)
        if parsed and parsed.get("name"):
            countries.add(infer_country_from_label(parsed["name"]))
    return sorted(countries)


def get_servers_for_subscription(subscription: dict) -> tuple:
    """Returns (source_info, source_decoded) depending on mode."""
    use_manual = (get_setting("use_manual_servers", "0") or "0") == "1"
    if use_manual:
        return None, None
    source_info = fetch_remote_json_source()
    return source_info, source_info["decoded"]


# ---------------------------------------------------------------------------
# API token helpers
# ---------------------------------------------------------------------------

def get_api_token_from_request() -> Optional[str]:
    try:
        from flask import request as flask_request
        auth = flask_request.headers.get("Authorization", "")
        if auth:
            m = re.match(r"Bearer\s+(.+)", auth, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        header_token = flask_request.headers.get("X-API-Token", "")
        if header_token:
            return header_token.strip()
        token = flask_request.args.get("token") or flask_request.form.get("token")
        if token:
            return str(token).strip()
    except Exception:
        pass
    return None
