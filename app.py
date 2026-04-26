"""Flask application: factory, routes, and all admin/API endpoints."""

import base64
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect as flask_redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import (
    CACHE_DIR,
    DB_PATH,
    SECRET_KEY,
    UPLOADS_DIR,
    API_RATE_LIMIT,
    LOGIN_RATE_LIMIT,
)
from models import (
    all_plans,
    all_subscriptions,
    app_is_installed,
    collect_dashboard_stats,
    fetch_plan,
    fetch_subscription,
    get_branding_settings,
    get_setting,
    initialize_database,
    set_setting,
    set_settings,
    json_setting_array,
)
from functions import (
    build_default_subscription_payload,
    build_happ_config,
    build_happ_profile_header,
    collect_countries_from_manual,
    collect_countries_from_source,
    ensure_dirs,
    fetch_remote_json_source,
    get_api_token_from_request,
    next_expiry_from_days,
    normalize_accent_color,
    now_utc,
    parse_datetime_to_utc,
    rate_limit,
    slugify,
    subscription_public_id,
    subscription_status_detail,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def verify_csrf() -> None:
    token = request.form.get("_csrf", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400, "Invalid CSRF token.")


app.jinja_env.globals["csrf_token"] = csrf_token


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not app_is_installed():
            return flask_redirect(url_for("setup"))
        if not session.get("admin_logged_in"):
            return flask_redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def require_setup(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not app_is_installed():
            return flask_redirect(url_for("setup"))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Template context helpers
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    return {
        "branding": get_branding_settings(),
        "app_url": lambda p="": url_for("index") + p.lstrip("/"),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if not app_is_installed():
        return flask_redirect(url_for("setup"))
    if session.get("admin_logged_in"):
        return flask_redirect(url_for("dashboard"))
    return flask_redirect(url_for("login"))


# ---- Setup ----

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if app_is_installed():
        return flask_redirect(url_for("dashboard"))
    error = None
    defaults = {
        "admin_username": request.form.get("admin_username", "admin"),
        "vpn_name": request.form.get("vpn_name", "XAMBoost VPN"),
        "vpn_description": request.form.get("vpn_description", "Fast self-updating VPN subscription panel."),
        "accent_color": request.form.get("accent_color", "#22c55e"),
        "logo_url": request.form.get("logo_url", ""),
    }
    if request.method == "POST":
        try:
            if not rate_limit("setup", 8):
                raise RuntimeError("Too many setup attempts. Please wait a minute.")
            username = request.form.get("admin_username", "").strip()
            password = request.form.get("admin_password", "")
            password_confirm = request.form.get("admin_password_confirm", "")
            api_token = request.form.get("api_token", "").strip()
            vpn_name = request.form.get("vpn_name", "XAMBoost VPN").strip()
            vpn_desc = request.form.get("vpn_description", "").strip()
            accent = normalize_accent_color(request.form.get("accent_color", "#22c55e"))
            logo_url = request.form.get("logo_url", "").strip()

            if not username or len(username) < 3:
                raise RuntimeError("Admin username must be at least 3 characters.")
            if not password or len(password) < 8:
                raise RuntimeError("Admin password must be at least 8 characters.")
            if password != password_confirm:
                raise RuntimeError("Password confirmation does not match.")
            if not api_token or len(api_token) < 16:
                raise RuntimeError("API token must be at least 16 characters.")

            uploaded_logo = _save_uploaded_logo("logo_file")
            if uploaded_logo:
                logo_url = uploaded_logo

            initialize_database()
            set_settings({
                "admin_username": username,
                "admin_password_hash": generate_password_hash(password),
                "api_token_hash": generate_password_hash(api_token),
                "vpn_name": vpn_name or "XAMBoost VPN",
                "vpn_description": vpn_desc,
                "logo_url": logo_url,
                "accent_color": accent,
                "server_renames": "{}",
            })
            flash("Setup complete. Sign in with the admin account you just created.", "success")
            return flask_redirect(url_for("login"))
        except Exception as exc:
            error = str(exc)
    return render_template("setup.html", error=error, defaults=defaults)


# ---- Login / Logout ----

@app.route("/login", methods=["GET", "POST"])
@require_setup
def login():
    if session.get("admin_logged_in"):
        return flask_redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        try:
            if not rate_limit("login", LOGIN_RATE_LIMIT):
                raise RuntimeError("Too many login attempts. Please wait a minute.")
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            stored_user = get_setting("admin_username")
            stored_hash = get_setting("admin_password_hash")
            if (
                not stored_user
                or not stored_hash
                or not secrets.compare_digest(username, stored_user)
                or not check_password_hash(stored_hash, password)
            ):
                raise RuntimeError("Invalid username or password.")
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = username
            flash("Welcome back.", "success")
            return flask_redirect(url_for("dashboard"))
        except Exception as exc:
            error = str(exc)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return flask_redirect(url_for("login"))


# ---- Dashboard ----

@app.route("/dashboard")
@require_admin
def dashboard():
    stats = collect_dashboard_stats()
    recent_subs = all_subscriptions()[:5]
    server_count = 0
    countries: list = []
    source_error = None
    try:
        happ = build_happ_config()
        server_count = happ.get("server_count", 0)
        countries = happ.get("countries", [])
    except Exception as exc:
        source_error = str(exc)
    manual_servers = get_setting("manual_servers", "") or ""
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_subs=recent_subs,
        server_count=server_count,
        countries=countries,
        source_error=source_error,
        manual_servers_preview=manual_servers[:200] if manual_servers else "",
    )


# ---- Subscriptions ----

@app.route("/subscriptions", methods=["GET", "POST"])
@require_admin
def subscriptions():
    plans = all_plans()
    editing = None
    error = None
    edit_id = request.args.get("edit")
    if edit_id:
        editing = fetch_subscription(edit_id)

    if request.method == "POST":
        try:
            verify_csrf()
            action = request.form.get("action", "")
            conn = _get_db()

            if action == "create":
                sub_id = request.form.get("id", "").strip()
                sub_id = slugify(sub_id) if sub_id else subscription_public_id()
                name = request.form.get("name", "").strip()
                description = request.form.get("description", "").strip()
                badge = request.form.get("badge", "").strip()
                telegram_id = request.form.get("telegram_id", "").strip()
                status = "disabled" if request.form.get("status") == "disabled" else "active"
                plan_id = request.form.get("plan_id", "").strip()
                duration_days = max(0, int(request.form.get("duration_days", 0) or 0))
                expires_input = parse_datetime_to_utc(request.form.get("expires_at", ""))
                plan = fetch_plan(plan_id) if plan_id else None

                if not name:
                    raise RuntimeError("Subscription name is required.")
                if plan_id and plan is None:
                    raise RuntimeError("Selected plan does not exist.")
                if expires_input is None:
                    days = duration_days if duration_days > 0 else int((plan or {}).get("duration_days", 30) or 30)
                    expires_input = next_expiry_from_days(None, max(1, days))

                conn.execute(
                    "INSERT INTO subscriptions (id, name, description, badge, telegram_id, status, created_at, expires_at, plan_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (sub_id, name, description, badge, telegram_id, status, now_utc(), expires_input, plan_id or None),
                )
                conn.commit()
                flash("Subscription created successfully.", "success")
                return flask_redirect(url_for("subscriptions"))

            if action == "update":
                sub_id = request.form.get("id", "").strip()
                sub = fetch_subscription(sub_id)
                if not sub:
                    raise RuntimeError("Subscription not found.")
                name = request.form.get("name", "").strip()
                description = request.form.get("description", "").strip()
                badge = request.form.get("badge", "").strip()
                telegram_id = request.form.get("telegram_id", "").strip()
                status = "disabled" if request.form.get("status") == "disabled" else "active"
                plan_id = request.form.get("plan_id", "").strip()
                expires_input = parse_datetime_to_utc(request.form.get("expires_at", ""))
                if not name:
                    raise RuntimeError("Subscription name is required.")
                if expires_input is None:
                    raise RuntimeError("Expiry date must be valid.")
                conn.execute(
                    "UPDATE subscriptions SET name=?,description=?,badge=?,telegram_id=?,status=?,expires_at=?,plan_id=? WHERE id=?",
                    (name, description, badge, telegram_id, status, expires_input, plan_id or None, sub_id),
                )
                conn.commit()
                flash("Subscription updated.", "success")
                return flask_redirect(url_for("subscriptions"))

            if action == "extend":
                sub_id = request.form.get("id", "").strip()
                sub = fetch_subscription(sub_id)
                if not sub:
                    raise RuntimeError("Subscription not found.")
                plan_id = request.form.get("extend_plan_id", "").strip()
                days = max(0, int(request.form.get("extend_days", 0) or 0))
                if plan_id:
                    plan = fetch_plan(plan_id)
                    if plan is None:
                        raise RuntimeError("Selected plan does not exist.")
                    days = int(plan.get("duration_days", 0) or 0)
                if days <= 0:
                    raise RuntimeError("Extension period must be greater than zero.")
                new_expiry = next_expiry_from_days(sub.get("expires_at"), days)
                conn.execute(
                    "UPDATE subscriptions SET expires_at=?, plan_id=? WHERE id=?",
                    (new_expiry, plan_id or sub.get("plan_id"), sub_id),
                )
                conn.commit()
                flash("Subscription extended.", "success")
                return flask_redirect(url_for("subscriptions"))

            if action == "toggle":
                sub_id = request.form.get("id", "").strip()
                target_status = "disabled" if request.form.get("target_status") == "disabled" else "active"
                conn.execute("UPDATE subscriptions SET status=? WHERE id=?", (target_status, sub_id))
                conn.commit()
                flash("Subscription status updated.", "success")
                return flask_redirect(url_for("subscriptions"))

            if action == "delete":
                sub_id = request.form.get("id", "").strip()
                conn.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
                conn.commit()
                flash("Subscription deleted.", "success")
                return flask_redirect(url_for("subscriptions"))

            raise RuntimeError("Unknown action.")
        except Exception as exc:
            error = str(exc)

    subs = all_subscriptions()
    form_values = editing or {
        "id": "", "name": "", "description": "", "badge": "", "telegram_id": "",
        "status": "active", "expires_at": "", "plan_id": "",
    }
    default_expires = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M")
    return render_template(
        "subscriptions.html",
        subscriptions=subs,
        plans=plans,
        editing=editing,
        form_values=form_values,
        error=error,
        default_expires=default_expires,
    )


# ---- Plans ----

@app.route("/plans", methods=["GET", "POST"])
@require_admin
def plans():
    error = None
    editing = None
    edit_id = request.args.get("edit")
    if edit_id:
        editing = fetch_plan(edit_id)

    if request.method == "POST":
        try:
            verify_csrf()
            action = request.form.get("action", "")
            conn = _get_db()

            if action == "create":
                pid = request.form.get("id", "").strip()
                name = request.form.get("name", "").strip()
                duration = max(1, int(request.form.get("duration_days", 30) or 30))
                price = round(float(request.form.get("price", 0) or 0), 2)
                if not name:
                    raise RuntimeError("Plan name is required.")
                if not pid:
                    pid = slugify(name) + "-" + subscription_public_id()[:6]
                else:
                    pid = slugify(pid)
                conn.execute(
                    "INSERT INTO plans (id, name, duration_days, price) VALUES (?,?,?,?)",
                    (pid, name, duration, price),
                )
                conn.commit()
                flash("Plan created.", "success")
                return flask_redirect(url_for("plans"))

            if action == "update":
                pid = request.form.get("id", "").strip()
                name = request.form.get("name", "").strip()
                duration = max(1, int(request.form.get("duration_days", 30) or 30))
                price = round(float(request.form.get("price", 0) or 0), 2)
                if not name:
                    raise RuntimeError("Plan name is required.")
                conn.execute(
                    "UPDATE plans SET name=?, duration_days=?, price=? WHERE id=?",
                    (name, duration, price, pid),
                )
                conn.commit()
                flash("Plan updated.", "success")
                return flask_redirect(url_for("plans"))

            if action == "delete":
                pid = request.form.get("id", "").strip()
                conn.execute("DELETE FROM plans WHERE id=?", (pid,))
                conn.commit()
                flash("Plan deleted.", "success")
                return flask_redirect(url_for("plans"))

            raise RuntimeError("Unknown action.")
        except Exception as exc:
            error = str(exc)

    all_p = all_plans()
    form_values = editing or {"id": "", "name": "", "duration_days": 30, "price": 0}
    return render_template("plans.html", plans=all_p, editing=editing, form_values=form_values, error=error)


# ---- Settings ----

@app.route("/settings", methods=["GET", "POST"])
@require_admin
def settings():
    error = None
    if request.method == "POST":
        try:
            verify_csrf()
            action = request.form.get("action", "")

            if action == "save_branding":
                branding = get_branding_settings()
                vpn_name = request.form.get("vpn_name", branding["vpn_name"]).strip()
                description = request.form.get("vpn_description", branding["vpn_description"]).strip()
                logo_url = request.form.get("logo_url", branding["logo_url"]).strip()
                accent = normalize_accent_color(request.form.get("accent_color", branding["accent_color"]))
                uploaded_logo = _save_uploaded_logo("logo_file")
                if uploaded_logo:
                    logo_url = uploaded_logo
                set_settings({
                    "vpn_name": vpn_name or "XAMBoost VPN",
                    "vpn_description": description,
                    "logo_url": logo_url,
                    "accent_color": accent,
                })
                flash("Branding settings saved.", "success")
                return flask_redirect(url_for("settings"))

            if action == "save_source":
                use_manual = "1" if request.form.get("use_manual_servers") == "1" else "0"
                manual_servers = request.form.get("manual_servers", "").strip()
                server_renames = request.form.get("server_renames", "{}").strip()
                response_format = request.form.get("response_format", "happ").strip()
                json_source_url = request.form.get("json_source_url", "").strip()
                try:
                    decoded = json.loads(server_renames)
                    if not isinstance(decoded, dict):
                        raise ValueError()
                except Exception:
                    raise RuntimeError("Server renames must be a valid JSON object.")
                if json_source_url and not json_source_url.startswith(("http://", "https://")):
                    raise RuntimeError("Source URL is invalid.")
                updates = {
                    "server_renames": json.dumps(decoded, ensure_ascii=False),
                    "use_manual_servers": use_manual,
                    "manual_servers": manual_servers,
                    "response_format": response_format,
                }
                if json_source_url:
                    updates["json_source_url"] = json_source_url
                set_settings(updates)
                flash("Source settings saved.", "success")
                return flask_redirect(url_for("settings"))

            if action == "rotate_api_token":
                new_token = request.form.get("new_api_token", "").strip()
                if not new_token or len(new_token) < 16:
                    raise RuntimeError("New API token must be at least 16 characters.")
                set_setting("api_token_hash", generate_password_hash(new_token))
                flash("API token rotated successfully.", "success")
                return flask_redirect(url_for("settings"))

            raise RuntimeError("Unknown settings action.")
        except Exception as exc:
            error = str(exc)

    from config import DEFAULT_JSON_SOURCE_URL as _DEFAULT_URL
    branding = get_branding_settings()
    server_renames = get_setting("server_renames", "{}") or "{}"
    use_manual = get_setting("use_manual_servers", "1") == "1"
    manual_servers = get_setting("manual_servers", "") or ""
    response_format = get_setting("response_format", "happ") or "happ"
    json_source_url = get_setting("json_source_url", _DEFAULT_URL) or _DEFAULT_URL
    return render_template(
        "settings.html",
        branding=branding,
        server_renames=server_renames,
        use_manual=use_manual,
        manual_servers=manual_servers,
        response_format=response_format,
        json_source_url=json_source_url,
        error=error,
    )


# ---- Subscription public page ----

@app.route("/subscription/<sub_id>")
@require_setup
def subscription_page(sub_id: str):
    sub = fetch_subscription(sub_id)
    if sub is None:
        if _wants_json() or request.args.get("format"):
            return jsonify({"ok": False, "error": "Subscription not found."}), 404
        abort(404)

    status = subscription_status_detail(sub)
    if not status["ok"]:
        if _wants_json() or request.args.get("format"):
            return jsonify({"ok": False, "error": status["reason"]}), status["code"]
        return render_template("subscription_page.html", subscription=sub, status=status, branding=get_branding_settings())

    fmt = request.args.get("format", "").lower().strip()

    # Fetch source (remote or None for manual mode)
    use_manual = (get_setting("use_manual_servers", "0") or "0") == "1"
    source_decoded = None
    source_raw = None
    try:
        if not use_manual:
            src_info = fetch_remote_json_source()
            source_decoded = src_info["decoded"]
            source_raw = src_info["raw"]
        payload = build_default_subscription_payload(sub, source_decoded)
        happ = build_happ_config(source_decoded)
    except Exception as exc:
        if _wants_json() or fmt:
            return jsonify({"ok": False, "error": str(exc)}), 502
        abort(502)

    if fmt == "happ":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        return Response(
            base64.b64encode((header + servers_text).encode("utf-8")),
            content_type="text/plain; charset=utf-8",
        )

    if fmt in ("happ_config", "happ_json"):
        cfg = dict(happ["config"])
        cfg["meta"] = payload.get("meta")
        return jsonify(cfg)

    if fmt == "happ_base64":
        cfg = dict(happ["config"])
        cfg["meta"] = payload.get("meta")
        encoded = base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode("utf-8"))
        return Response(encoded, content_type="text/plain; charset=utf-8")

    if fmt == "happ_wrapped":
        cfg = dict(happ["config"])
        cfg["meta"] = payload.get("meta")
        return jsonify({"happ": cfg})

    if fmt == "happ_combo":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        envelope = {
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "routing": happ["config"].get("route"),
        }
        return jsonify(envelope)

    if fmt == "happ_combo_base64":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        envelope = {
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "routing": happ["config"].get("route"),
        }
        encoded = base64.b64encode(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
        return Response(encoded, content_type="text/plain; charset=utf-8")

    if fmt == "happ_split":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        return jsonify({
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "routing": happ["config"].get("route"),
        })

    if fmt == "happ_split_base64":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        envelope = {
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "routing": happ["config"].get("route"),
        }
        encoded = base64.b64encode(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
        return Response(encoded, content_type="text/plain; charset=utf-8")

    if fmt == "happ_geo":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        return jsonify({
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "geoip": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
            "geosite": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
        })

    if fmt == "happ_geo_base64":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        envelope = {
            "subscription": base64.b64encode((header + servers_text).encode("utf-8")).decode(),
            "geoip": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
            "geosite": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
        }
        encoded = base64.b64encode(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
        return Response(encoded, content_type="text/plain; charset=utf-8")

    if fmt == "list":
        return Response("\n".join(payload.get("servers", [])), content_type="text/plain; charset=utf-8")

    if fmt == "base64":
        servers_text = "\n".join(payload.get("servers", []))
        header = build_happ_profile_header(sub, payload)
        return Response(
            base64.b64encode((header + servers_text).encode("utf-8")),
            content_type="text/plain; charset=utf-8",
        )

    if fmt == "source":
        if not use_manual and source_raw:
            return Response(source_raw, content_type="application/json; charset=utf-8")
        manual_raw = get_setting("manual_servers", "") or ""
        return Response(manual_raw, content_type="text/plain; charset=utf-8")

    if not fmt and _wants_json():
        return jsonify(payload)

    # HTML page
    countries = collect_countries_from_source(source_decoded) if source_decoded else collect_countries_from_manual()
    sub_url = request.host_url.rstrip("/") + "/subscription/" + sub_id
    return render_template(
        "subscription_page.html",
        subscription=sub,
        status=status,
        branding=get_branding_settings(),
        countries=countries,
        sub_url=sub_url,
        happ_url=sub_url + "?format=happ",
        json_url=sub_url + "?response=json",
    )


# ---- API ----

@app.route("/api")
@app.route("/api/<path:route>")
@require_setup
def api(route: str = ""):
    if not rate_limit("api", API_RATE_LIMIT):
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again in a minute."}), 429

    api_token = get_api_token_from_request()
    token_hash = get_setting("api_token_hash")
    if not api_token or not token_hash or not check_password_hash(token_hash, api_token):
        return jsonify({"ok": False, "error": "Invalid API token."}), 401

    route = route.strip("/")

    if route == "":
        return jsonify({
            "ok": True,
            "message": "VPN SaaS API is online.",
            "endpoints": [
                "create-subscription", "extend-subscription", "delete-subscription",
                "disable-subscription", "enable-subscription", "assign-telegram",
                "subscription/{id}", "subscription/{id}/happ", "subscription/{id}/source",
            ],
        })

    # subscription/{id}/source
    _use_manual = (get_setting("use_manual_servers", "0") or "0") == "1"

    def _get_source():
        if _use_manual:
            return None, None
        src = fetch_remote_json_source()
        return src["decoded"], src["raw"]

    m = re.match(r"^subscription/([A-Za-z0-9_\-]+)/source$", route)
    if m:
        sub = _api_fetch_sub_or_error(m.group(1))
        if isinstance(sub, tuple):
            return sub
        status = subscription_status_detail(sub)
        if not status["ok"]:
            return jsonify({"ok": False, "error": status["reason"]}), status["code"]
        _, raw = _get_source()
        if raw:
            return Response(raw, content_type="application/json; charset=utf-8")
        manual_raw = get_setting("manual_servers", "") or ""
        return Response(manual_raw, content_type="text/plain; charset=utf-8")

    # subscription/{id}/happ
    m = re.match(r"^subscription/([A-Za-z0-9_\-]+)/happ$", route)
    if m:
        sub = _api_fetch_sub_or_error(m.group(1))
        if isinstance(sub, tuple):
            return sub
        status = subscription_status_detail(sub)
        if not status["ok"]:
            return jsonify({"ok": False, "error": status["reason"]}), status["code"]
        try:
            src_decoded, _ = _get_source()
            happ = build_happ_config(src_decoded)
            return jsonify(happ["config"])
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502

    # subscription/{id}
    m = re.match(r"^subscription/([A-Za-z0-9_\-]+)$", route)
    if m:
        sub = _api_fetch_sub_or_error(m.group(1))
        if isinstance(sub, tuple):
            return sub
        status = subscription_status_detail(sub)
        if not status["ok"]:
            return jsonify({"ok": False, "error": status["reason"]}), status["code"]
        try:
            src_decoded, _ = _get_source()
            payload = build_default_subscription_payload(sub, src_decoded)
            return jsonify(payload)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502

    # Named routes
    try:
        conn = _get_db()

        if route == "create-subscription":
            sub_id = (request.values.get("id") or "").strip()
            sub_id = slugify(sub_id) if sub_id else subscription_public_id()
            name = (request.values.get("name") or "").strip()
            description = (request.values.get("description") or "").strip()
            badge = (request.values.get("badge") or "").strip()
            telegram_id = (request.values.get("telegram_id") or "").strip()
            status_val = "disabled" if request.values.get("status") == "disabled" else "active"
            plan_id = (request.values.get("plan_id") or "").strip()
            plan = fetch_plan(plan_id) if plan_id else None
            expires_at = parse_datetime_to_utc(request.values.get("expires_at") or "")
            dur_days = max(0, int(request.values.get("days") or request.values.get("duration_days") or 0))
            if not name:
                return jsonify({"ok": False, "error": "Subscription name is required."}), 422
            if plan_id and plan is None:
                return jsonify({"ok": False, "error": "Plan not found."}), 404
            if expires_at is None:
                days = dur_days if dur_days > 0 else int((plan or {}).get("duration_days", 30) or 30)
                expires_at = next_expiry_from_days(None, max(1, days))
            try:
                conn.execute(
                    "INSERT INTO subscriptions (id,name,description,badge,telegram_id,status,created_at,expires_at,plan_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (sub_id, name, description, badge, telegram_id, status_val, now_utc(), expires_at, plan_id or None),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return jsonify({"ok": False, "error": "A record with the same identifier already exists."}), 409
            sub = fetch_subscription(sub_id)
            base = request.host_url.rstrip("/")
            return jsonify({
                "ok": True, "message": "Subscription created.",
                "subscription": sub,
                "links": {
                    "default": f"{base}/subscription/{sub_id}",
                    "json": f"{base}/subscription/{sub_id}?response=json",
                    "happ": f"{base}/subscription/{sub_id}?format=happ",
                    "source": f"{base}/subscription/{sub_id}?format=source",
                },
            }), 201

        if route == "extend-subscription":
            sub_id = (request.values.get("id") or "").strip()
            sub = _api_fetch_sub_or_error(sub_id)
            if isinstance(sub, tuple):
                return sub
            plan_id = (request.values.get("plan_id") or "").strip()
            days = max(0, int(request.values.get("days") or 0))
            if plan_id:
                plan = fetch_plan(plan_id)
                if plan is None:
                    return jsonify({"ok": False, "error": "Plan not found."}), 404
                days = int(plan.get("duration_days", 0) or 0)
            if days <= 0:
                return jsonify({"ok": False, "error": "Extension period must be greater than zero."}), 422
            new_expiry = next_expiry_from_days(sub.get("expires_at"), days)
            conn.execute(
                "UPDATE subscriptions SET expires_at=?, plan_id=? WHERE id=?",
                (new_expiry, plan_id or sub.get("plan_id"), sub_id),
            )
            conn.commit()
            return jsonify({"ok": True, "message": "Subscription extended.", "subscription": fetch_subscription(sub_id)})

        if route == "delete-subscription":
            sub_id = (request.values.get("id") or "").strip()
            sub = _api_fetch_sub_or_error(sub_id)
            if isinstance(sub, tuple):
                return sub
            conn.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
            conn.commit()
            return jsonify({"ok": True, "message": "Subscription deleted.", "id": sub_id})

        if route in ("disable-subscription", "enable-subscription"):
            sub_id = (request.values.get("id") or "").strip()
            sub = _api_fetch_sub_or_error(sub_id)
            if isinstance(sub, tuple):
                return sub
            target_status = "disabled" if route == "disable-subscription" else "active"
            conn.execute("UPDATE subscriptions SET status=? WHERE id=?", (target_status, sub_id))
            conn.commit()
            return jsonify({"ok": True, "message": "Subscription status updated.", "subscription": fetch_subscription(sub_id)})

        if route == "assign-telegram":
            sub_id = (request.values.get("id") or "").strip()
            tg_id = (request.values.get("telegram_id") or "").strip()
            if not tg_id:
                return jsonify({"ok": False, "error": "telegram_id is required."}), 422
            sub = _api_fetch_sub_or_error(sub_id)
            if isinstance(sub, tuple):
                return sub
            conn.execute("UPDATE subscriptions SET telegram_id=? WHERE id=?", (tg_id, sub_id))
            conn.commit()
            return jsonify({"ok": True, "message": "Telegram ID assigned.", "subscription": fetch_subscription(sub_id)})

        return jsonify({"ok": False, "error": "Unknown API route.", "route": route}), 404

    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "A record with the same identifier already exists."}), 409
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    from models import get_fresh_db
    if "db" not in g:
        g.db = get_fresh_db()
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _api_fetch_sub_or_error(sub_id: str):
    sub = fetch_subscription(sub_id)
    if sub is None:
        return jsonify({"ok": False, "error": "Subscription not found."}), 404
    return sub


def _wants_json() -> bool:
    for flag in (request.args.get("response"), request.args.get("view"), request.args.get("output")):
        if flag and flag.lower() == "json":
            return True
    accept = request.headers.get("Accept", "").lower()
    if accept and "application/json" in accept and "text/html" not in accept:
        return True
    return request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest"


def _save_uploaded_logo(field_name: str = "logo_file") -> Optional[str]:
    file = request.files.get(field_name)
    if file is None or file.filename == "":
        return None
    allowed_mimes = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif"}
    # Read a small chunk to sniff mime type
    header_bytes = file.read(16)
    file.seek(0)
    import imghdr
    fmt = imghdr.what(None, h=header_bytes)
    mime_map = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
    mime = mime_map.get(fmt or "", "")
    if mime not in allowed_mimes:
        raise RuntimeError("Unsupported logo format. Use PNG, JPG, WEBP, or GIF.")
    ext = allowed_mimes[mime]
    import secrets as _secrets
    filename = f"logo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{_secrets.token_hex(4)}.{ext}"
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    target = os.path.join(UPLOADS_DIR, secure_filename(filename))
    file.save(target)
    return request.host_url.rstrip("/") + "/uploads/" + filename


# Serve uploads
@app.route("/uploads/<filename>")
def uploaded_file(filename: str):
    from flask import send_from_directory
    return send_from_directory(UPLOADS_DIR, filename)


# ---------------------------------------------------------------------------
# Bootstrap DB on startup
# ---------------------------------------------------------------------------

def _bootstrap():
    ensure_dirs()
    if not os.path.exists(DB_PATH):
        initialize_database()
    else:
        from models import get_fresh_db, _tables_exist, _init_db
        conn = get_fresh_db()
        if not _tables_exist(conn):
            _init_db(conn)
        conn.close()


_bootstrap()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
