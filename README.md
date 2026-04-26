# XAMBooster Python Edition

Flask + SQLite rewrite of the XAMBoost VPN subscription panel.

## Features

- 4 regular VPN servers (Germany 🇩🇪, Netherlands 🇳🇱, Sweden 🇸🇪, Poland 🇵🇱)
- 1 LTE/Whitelist server 📱
- All subscription formats: `happ`, `base64`, `list`, `happ_combo`, `happ_geo`, and more
- Profile header with `# announce: base64:...` field
- Admin dashboard, subscription & plan management
- Token-protected REST API
- CSRF protection, session auth, file-based rate limiting

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000 — first run redirects to `/setup`.

## Setup

1. Create admin username + password (min 8 chars)
2. Set API token (min 16 chars)
3. Configure VPN name and branding

## Configuration

### Edit server URIs

Go to **Settings → Server List** and replace `PLACEHOLDER_UUID` with real UUIDs:

```
vless://your-real-uuid@germany.yourdomain.com:443?type=tcp&security=tls#🇩🇪 Германия
vless://your-real-uuid@netherlands.yourdomain.com:443?type=tcp&security=tls#🇳🇱 Нидерланды
vless://your-real-uuid@sweden.yourdomain.com:443?type=tcp&security=tls#🇸🇪 Швеция
vless://your-real-uuid@poland.yourdomain.com:443?type=tcp&security=tls#🇵🇱 Польша
vless://your-real-uuid@lte.yourdomain.com:443?type=tcp&security=tls#📱 LTE Whitelist
```

## Subscription Formats

| URL | Description |
|-----|-------------|
| `/subscription/{id}` | HTML page |
| `/subscription/{id}?format=happ` | Base64-encoded Happ import |
| `/subscription/{id}?format=base64` | Base64 URI list |
| `/subscription/{id}?format=list` | Plain URI list |
| `/subscription/{id}?format=happ_combo` | Subscription + routing JSON |
| `/subscription/{id}?format=happ_geo` | Subscription + geoip links |
| `/subscription/{id}?format=source` | Raw manual server list |
| `/subscription/{id}?response=json` | Full JSON payload |

## API

All API endpoints require token auth: `Authorization: Bearer <token>` or `?token=<token>`.

```
GET  /api                              — API info
POST /api/create-subscription          — Create subscription
POST /api/extend-subscription          — Extend subscription
POST /api/delete-subscription          — Delete subscription
POST /api/disable-subscription         — Disable subscription
POST /api/enable-subscription          — Enable subscription
POST /api/assign-telegram              — Assign Telegram ID
GET  /api/subscription/{id}            — Get subscription payload
GET  /api/subscription/{id}/happ       — Get sing-box config
GET  /api/subscription/{id}/source     — Get raw server list
```

## Production Deployment

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Or with Docker:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
```
