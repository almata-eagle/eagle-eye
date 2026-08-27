"""
Eagle Eye — API
===============
The client-facing counterpart to Eagle Talon. Where Talon is an operator's
console for managing hundreds of domains across many client workspaces, Eye
is the individual client's own portal — usually 1-3 domains, framed as a
personal security scorecard rather than a SOC console. Same scan engine
underneath (scanner.py/techstack.py, copied unchanged from Talon), different
audience and different information shape.

Two modes, both real:
  - Independent: the client signs up here directly, scans their own domain(s).
  - Tied to Eagle Talon: if an operator has already scanned this client's
    domain in Talon, Eye reads that result directly from Talon's database
    (mounted read-only) instead of re-scanning — see _read_talon_scan().

Auth is intentionally minimal for a prototype: PBKDF2-HMAC-SHA256 password
hashing (stdlib only, no extra dependency) + bearer tokens persisted in
SQLite. Real production use would want rate limiting, email verification,
password reset, and HTTPS enforcement — none of that is here yet.
"""
import calendar
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import techstack
from scanner import scan_domain, tier_for_score

app = FastAPI(title="Eagle Eye API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = Path(os.environ.get("EAGLE_EYE_DB_PATH", str(Path(__file__).parent / "eagle_eye.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Path to Eagle Talon's database, shared via a Docker volume — used both to
# read a domain's existing Talon scan (for the "tied to Talon" display) and,
# now, to write back a client-initiated scan so the operator sees it too.
TALON_DB_PATH = os.environ.get("EAGLE_TALON_DB_PATH_LINK")


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
        password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
        company_name TEXT, created_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY, account_id TEXT NOT NULL, created_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS account_domains (
        account_id TEXT NOT NULL, domain TEXT NOT NULL,
        linked_talon_client_id TEXT, created_at TEXT NOT NULL,
        PRIMARY KEY (account_id, domain))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS eye_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,
        domain TEXT NOT NULL, data TEXT NOT NULL, scanned_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,
        label TEXT NOT NULL, tech_key TEXT, version TEXT,
        last_checked_at TEXT, cached_cves TEXT, created_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS monitors (
        account_id TEXT NOT NULL, domain TEXT NOT NULL,
        frequency_hours INTEGER NOT NULL DEFAULT 24, enabled INTEGER NOT NULL DEFAULT 1,
        last_checked_at TEXT, created_at TEXT NOT NULL,
        PRIMARY KEY (account_id, domain))""")
    # Safe additive migration for the Daily/Weekly/Monthly scheduling model —
    # mirrors Talon's identical migration. Existing monitors default to "daily".
    mon_cols = [r[1] for r in conn.execute("PRAGMA table_info(monitors)").fetchall()]
    if "freq_type" not in mon_cols:
        conn.execute("ALTER TABLE monitors ADD COLUMN freq_type TEXT NOT NULL DEFAULT 'daily'")
        conn.execute("ALTER TABLE monitors ADD COLUMN day_of_week INTEGER")
        conn.execute("ALTER TABLE monitors ADD COLUMN day_of_month INTEGER")
    conn.execute("""CREATE TABLE IF NOT EXISTS eye_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL, domain TEXT NOT NULL,
        severity TEXT NOT NULL, code TEXT NOT NULL, data TEXT NOT NULL,
        created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0)""")
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Auth — PBKDF2, stdlib only. Real system would use bcrypt/argon2, add
# rate-limiting on login, and require email verification before use.
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return salt, h.hex()


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, h = _hash_password(password, salt)
    return secrets.compare_digest(h, expected_hash)


def _create_session(account_id: str) -> str:
    token = secrets.token_urlsafe(32)
    conn = _db()
    conn.execute("INSERT INTO sessions (token, account_id, created_at) VALUES (?, ?, ?)",
                 (token, account_id, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return token


def get_current_account(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header.")
    token = authorization[len("Bearer "):]
    conn = _db()
    row = conn.execute("""SELECT a.id, a.email, a.company_name FROM sessions s
                           JOIN accounts a ON a.id = s.account_id WHERE s.token=?""", (token,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Session expired or invalid — please log in again.")
    return {"id": row[0], "email": row[1], "company_name": row[2]}


# ---------------------------------------------------------------------------
# Talon linking — read-only cross-reference against Talon's own database.
# ---------------------------------------------------------------------------
def _read_talon_scan(client_id: str, domain: str) -> Optional[dict]:
    if not TALON_DB_PATH or not Path(TALON_DB_PATH).exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{TALON_DB_PATH}?mode=ro", uri=True)
        row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
        conn.close()
        return json.loads(row[0]) if row else None
    except Exception:
        return None


# Change-detection logic, intentionally duplicated (small) from Eagle Talon's
# main.py rather than shared across the two separate services/repos — see
# Talon's own copy for the canonical version if these ever need to diverge.
SCORE_DROP_ALERT_THRESHOLD = 10
TIER_RANK = {"clear": 3, "watch": 2, "high": 1, "critical": 0}


def _finding_codes(scan: dict) -> set:
    return {f.get("code") for c in scan.get("categories", []) for f in c.get("findings", []) if isinstance(f, dict)}


def _detect_changes(old: dict, new: dict) -> list[dict]:
    alerts = []
    old_score, new_score = old.get("overall_score", 100), new.get("overall_score", 100)
    old_tier, new_tier = old.get("tier", "clear"), new.get("tier", "clear")
    if old_score - new_score >= SCORE_DROP_ALERT_THRESHOLD:
        severity = "critical" if new_tier in ("high", "critical") else "warning"
        alerts.append({"severity": severity, "code": "score_drop", "data": {"old_score": old_score, "new_score": new_score}})
    if TIER_RANK.get(new_tier, 3) < TIER_RANK.get(old_tier, 3):
        alerts.append({"severity": "critical" if new_tier == "critical" else "warning",
                        "code": "tier_worsened", "data": {"old_tier": old_tier, "new_tier": new_tier}})
    old_codes, new_codes = _finding_codes(old), _finding_codes(new)
    if "urlhaus_hit" in new_codes and "urlhaus_hit" not in old_codes:
        alerts.append({"severity": "critical", "code": "new_threat_intel_hit", "data": {}})
    if "cve_detected" in new_codes and "cve_detected" not in old_codes:
        alerts.append({"severity": "critical", "code": "new_cve", "data": {}})
    if "cert_expired" in new_codes and "cert_expired" not in old_codes:
        alerts.append({"severity": "critical", "code": "cert_now_expired", "data": {}})
    return alerts


def _write_talon_scan(client_id: str, domain: str, result: dict) -> bool:
    """Writes a client-initiated Eagle Eye scan back into Talon's own
    database, so the operator sees it without needing Eye to duplicate a
    whole client-management UI. Preserves whatever sector/watchlist an
    operator already assigned in Talon — Eye's write-back only replaces the
    scan content itself, never the operator's own categorization — and runs
    the same change-detection Talon's monitoring uses, so a client's
    self-scan can trigger a real alert in Talon if something got worse."""
    if not TALON_DB_PATH or not Path(TALON_DB_PATH).exists():
        return False
    try:
        conn = sqlite3.connect(TALON_DB_PATH)  # read-write — no ?mode=ro
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL, domain TEXT NOT NULL,
            severity TEXT NOT NULL, code TEXT NOT NULL, data TEXT NOT NULL,
            created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0)""")

        old_row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
        old_scan = json.loads(old_row[0]) if old_row else None

        merged = dict(result)
        merged["sector"] = old_scan.get("sector", "Unassigned") if old_scan else "Unassigned"
        merged["watchlist"] = old_scan.get("watchlist", "Eagle Eye") if old_scan else "Eagle Eye"
        merged["last_scan_source"] = "eagle_eye"

        conn.execute("INSERT OR REPLACE INTO scans (client_id, domain, data, scanned_at) VALUES (?,?,?,?)",
                     (client_id, domain, json.dumps(merged), merged["scanned_at"]))

        if old_scan:
            for a in _detect_changes(old_scan, merged):
                conn.execute("INSERT INTO alerts (client_id, domain, severity, code, data, created_at, is_read) VALUES (?,?,?,?,?,?,0)",
                             (client_id, domain, a["severity"], a["code"], json.dumps(a["data"]), datetime.datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: str
    password: str
    company_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/signup")
def signup(req: SignupRequest):
    if not req.email or "@" not in req.email:
        raise HTTPException(400, "Provide a valid email address.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    conn = _db()
    if conn.execute("SELECT 1 FROM accounts WHERE email=?", (req.email.lower(),)).fetchone():
        conn.close()
        raise HTTPException(409, "An account with that email already exists.")
    account_id = secrets.token_hex(8)
    salt, pw_hash = _hash_password(req.password)
    created_at = datetime.datetime.utcnow().isoformat()
    conn.execute("INSERT INTO accounts (id, email, password_salt, password_hash, company_name, created_at) VALUES (?,?,?,?,?,?)",
                 (account_id, req.email.lower(), salt, pw_hash, req.company_name, created_at))
    conn.commit()
    conn.close()
    token = _create_session(account_id)
    return {"token": token, "account": {"id": account_id, "email": req.email.lower(), "company_name": req.company_name}}


@app.post("/api/login")
def login(req: LoginRequest):
    conn = _db()
    row = conn.execute("SELECT id, password_salt, password_hash, company_name FROM accounts WHERE email=?",
                        (req.email.lower(),)).fetchone()
    conn.close()
    if not row or not _verify_password(req.password, row[1], row[2]):
        raise HTTPException(401, "Incorrect email or password.")
    token = _create_session(row[0])
    return {"token": token, "account": {"id": row[0], "email": req.email.lower(), "company_name": row[3]}}


@app.get("/api/me")
def me(account: dict = Depends(get_current_account)):
    return account


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Domains — a client's own, small set (not Talon's hundreds-at-scale model)
# ---------------------------------------------------------------------------
class DomainAdd(BaseModel):
    domain: str


@app.post("/api/domains")
def add_domain(req: DomainAdd, account: dict = Depends(get_current_account)):
    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not domain or "." not in domain:
        raise HTTPException(400, "Provide a valid domain, e.g. yourcompany.com")
    conn = _db()
    conn.execute("INSERT OR IGNORE INTO account_domains (account_id, domain, created_at) VALUES (?,?,?)",
                 (account["id"], domain, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"domain": domain}


@app.get("/api/domains")
def list_domains(account: dict = Depends(get_current_account)):
    conn = _db()
    domains = conn.execute("SELECT domain, linked_talon_client_id FROM account_domains WHERE account_id=? ORDER BY created_at ASC",
                            (account["id"],)).fetchall()
    out = []
    for domain, talon_client_id in domains:
        latest = None
        if talon_client_id:
            latest = _read_talon_scan(talon_client_id, domain)
        if not latest:
            row = conn.execute("SELECT data FROM eye_scans WHERE account_id=? AND domain=? ORDER BY scanned_at DESC LIMIT 1",
                                (account["id"], domain)).fetchone()
            latest = json.loads(row[0]) if row else None
        out.append({
            "domain": domain,
            "linked_talon_client_id": talon_client_id,
            "overall_score": latest["overall_score"] if latest else None,
            "tier": latest["tier"] if latest else None,
            "last_scanned": latest.get("scanned_at") if latest else None,
        })
    conn.close()
    return {"domains": out}


@app.delete("/api/domains/{domain}")
def remove_domain(domain: str, account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("DELETE FROM account_domains WHERE account_id=? AND domain=?", (account["id"], domain))
    conn.execute("DELETE FROM eye_scans WHERE account_id=? AND domain=?", (account["id"], domain))
    conn.commit()
    conn.close()
    return {"deleted": domain}


def _run_scan_for_account_domain(account_id: str, domain: str) -> dict:
    """The one place a real scan happens for an Eye account's domain —
    manual 'Run new check' and the monitoring scheduler both call this, so
    Talon write-back and history-saving behave identically either way."""
    result = scan_domain(domain)

    conn = _db()
    conn.execute("INSERT INTO eye_scans (account_id, domain, data, scanned_at) VALUES (?,?,?,?)",
                 (account_id, domain, json.dumps(result), result["scanned_at"]))
    talon_row = conn.execute("SELECT linked_talon_client_id FROM account_domains WHERE account_id=? AND domain=?",
                              (account_id, domain)).fetchone()
    conn.commit()
    conn.close()

    talon_client_id = talon_row[0] if talon_row else None
    if talon_client_id:
        _write_talon_scan(talon_client_id, domain, result)

    return result


@app.post("/api/domains/{domain}/scan")
def scan_own_domain(domain: str, account: dict = Depends(get_current_account)):
    """Runs a real scan — same passive OSINT engine as Eagle Talon. If this
    domain is linked to a Talon client, the result also writes back into
    Talon's database so the operator sees client-initiated activity too."""
    try:
        return _run_scan_for_account_domain(account["id"], domain)
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {e}")


@app.get("/api/domains/{domain}/latest")
def get_latest(domain: str, account: dict = Depends(get_current_account)):
    conn = _db()
    talon_client_id = conn.execute("SELECT linked_talon_client_id FROM account_domains WHERE account_id=? AND domain=?",
                                    (account["id"], domain)).fetchone()
    talon_client_id = talon_client_id[0] if talon_client_id else None

    latest, source = None, "eye"
    if talon_client_id:
        latest = _read_talon_scan(talon_client_id, domain)
        if latest:
            source = "talon"
    if not latest:
        row = conn.execute("SELECT data FROM eye_scans WHERE account_id=? AND domain=? ORDER BY scanned_at DESC LIMIT 1",
                            (account["id"], domain)).fetchone()
        latest = json.loads(row[0]) if row else None
    conn.close()
    if not latest:
        raise HTTPException(404, "No scan yet for this domain — run one first.")
    latest["_source"] = source
    return latest


@app.get("/api/domains/{domain}/history")
def get_history(domain: str, account: dict = Depends(get_current_account)):
    """Score-over-time trend — Eye keeps full history per domain (unlike
    Talon, which keeps only the latest scan per client+domain), since
    'watch your score improve' is the point of the client-facing view."""
    conn = _db()
    rows = conn.execute("SELECT data, scanned_at FROM eye_scans WHERE account_id=? AND domain=? ORDER BY scanned_at ASC",
                         (account["id"], domain)).fetchall()
    conn.close()
    history = [{"scanned_at": r[1], "overall_score": json.loads(r[0])["overall_score"],
                "tier": json.loads(r[0])["tier"]} for r in rows]
    return {"domain": domain, "history": history}


class LinkTalonRequest(BaseModel):
    client_id: str


@app.post("/api/domains/{domain}/link-talon")
def link_talon(domain: str, req: LinkTalonRequest, account: dict = Depends(get_current_account)):
    if not TALON_DB_PATH:
        raise HTTPException(400, "This Eagle Eye instance isn't configured to read from Eagle Talon — running independently.")
    existing = _read_talon_scan(req.client_id, domain)
    if not existing:
        raise HTTPException(404, "No scan found for that domain under that Eagle Talon client ID. "
                                  "Ask your operator to scan it in Eagle Talon first, or check the client ID.")
    conn = _db()
    conn.execute("UPDATE account_domains SET linked_talon_client_id=? WHERE account_id=? AND domain=?",
                 (req.client_id, account["id"], domain))
    conn.commit()
    conn.close()
    return {"linked": True, "domain": domain, "client_id": req.client_id, "score": existing["overall_score"]}


@app.delete("/api/domains/{domain}/link-talon")
def unlink_talon(domain: str, account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("UPDATE account_domains SET linked_talon_client_id=NULL WHERE account_id=? AND domain=?",
                 (account["id"], domain))
    conn.commit()
    conn.close()
    return {"linked": False, "domain": domain}


@app.get("/")
def root():
    return {"service": "Eagle Eye API", "docs": "/docs", "talon_linked_mode": bool(TALON_DB_PATH)}


# ---------------------------------------------------------------------------
# Monitoring — scheduled re-scans + change-detection alerts, scoped to an
# Eye account rather than a Talon client. Same behavior either way: goes
# through _run_scan_for_account_domain(), so a monitored domain that's
# linked to Talon writes back there too, automatically.
# ---------------------------------------------------------------------------
def _check_eye_monitor(account_id: str, domain: str):
    conn = _db()
    row = conn.execute("SELECT data FROM eye_scans WHERE account_id=? AND domain=? ORDER BY scanned_at DESC LIMIT 1",
                        (account_id, domain)).fetchone()
    old_scan = json.loads(row[0]) if row else None
    conn.close()

    try:
        new_scan = _run_scan_for_account_domain(account_id, domain)
    except Exception:
        conn = _db()
        conn.execute("UPDATE monitors SET last_checked_at=? WHERE account_id=? AND domain=?",
                     (datetime.datetime.utcnow().isoformat(), account_id, domain))
        conn.commit(); conn.close()
        return

    if old_scan:
        for a in _detect_changes(old_scan, new_scan):
            conn = _db()
            conn.execute("INSERT INTO eye_alerts (account_id, domain, severity, code, data, created_at, is_read) VALUES (?,?,?,?,?,?,0)",
                         (account_id, domain, a["severity"], a["code"], json.dumps(a["data"]), datetime.datetime.utcnow().isoformat()))
            conn.commit(); conn.close()

    conn = _db()
    conn.execute("UPDATE monitors SET last_checked_at=? WHERE account_id=? AND domain=?",
                 (datetime.datetime.utcnow().isoformat(), account_id, domain))
    conn.commit(); conn.close()


def _monitor_is_due(freq_type: str, day_of_week: Optional[int], day_of_month: Optional[int],
                     last_checked_at: Optional[str], now: Optional[datetime.datetime] = None) -> bool:
    """Mirrors Talon's identical function — see its docstring for the full
    reasoning. Daily: once per calendar day. Weekly: on the chosen weekday.
    Monthly: on the chosen day-of-month, clamped to the month's real length."""
    now = now or datetime.datetime.utcnow()
    if not last_checked_at:
        return True
    last = datetime.datetime.fromisoformat(last_checked_at)
    if last.date() == now.date():
        return False
    if freq_type == "weekly":
        return now.weekday() == (day_of_week if day_of_week is not None else 0)
    if freq_type == "monthly":
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        target_day = min(day_of_month or 1, days_in_month)
        return now.day == target_day
    return True


def _eye_monitoring_scheduler_loop():
    while True:
        try:
            conn = _db()
            monitors = conn.execute("""SELECT account_id, domain, freq_type, day_of_week, day_of_month, last_checked_at
                                        FROM monitors WHERE enabled=1""").fetchall()
            conn.close()
            for account_id, domain, freq_type, day_of_week, day_of_month, last_checked_at in monitors:
                if _monitor_is_due(freq_type, day_of_week, day_of_month, last_checked_at):
                    _check_eye_monitor(account_id, domain)
        except Exception:
            pass
        time.sleep(60)


threading.Thread(target=_eye_monitoring_scheduler_loop, daemon=True).start()


class MonitorCreate(BaseModel):
    domain: str
    freq_type: str = "daily"
    day_of_week: Optional[int] = None
    day_of_month: Optional[int] = None


@app.post("/api/monitors")
def create_monitor(req: MonitorCreate, account: dict = Depends(get_current_account)):
    if req.freq_type not in ("daily", "weekly", "monthly"):
        raise HTTPException(400, "freq_type must be 'daily', 'weekly', or 'monthly'.")
    conn = _db()
    conn.execute("""INSERT INTO monitors (account_id, domain, freq_type, day_of_week, day_of_month, enabled, created_at)
                     VALUES (?,?,?,?,?,1,?)
                     ON CONFLICT(account_id, domain) DO UPDATE SET
                         freq_type=excluded.freq_type, day_of_week=excluded.day_of_week,
                         day_of_month=excluded.day_of_month, enabled=1""",
                 (account["id"], req.domain, req.freq_type, req.day_of_week, req.day_of_month,
                  datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"domain": req.domain, "freq_type": req.freq_type, "day_of_week": req.day_of_week,
            "day_of_month": req.day_of_month, "enabled": True}


@app.delete("/api/monitors/{domain}")
def disable_monitor(domain: str, account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("UPDATE monitors SET enabled=0 WHERE account_id=? AND domain=?", (account["id"], domain))
    conn.commit(); conn.close()
    return {"domain": domain, "enabled": False}


@app.get("/api/monitors")
def list_monitors(account: dict = Depends(get_current_account)):
    conn = _db()
    rows = conn.execute("""SELECT domain, freq_type, day_of_week, day_of_month, enabled, last_checked_at
                            FROM monitors WHERE account_id=?""", (account["id"],)).fetchall()
    conn.close()
    return {"monitors": [{"domain": r[0], "freq_type": r[1], "day_of_week": r[2], "day_of_month": r[3],
                           "enabled": bool(r[4]), "last_checked_at": r[5]} for r in rows]}


@app.post("/api/monitors/{domain}/check-now")
def check_monitor_now(domain: str, account: dict = Depends(get_current_account)):
    _check_eye_monitor(account["id"], domain)
    return {"checked": True, "domain": domain}


@app.get("/api/alerts")
def list_alerts(account: dict = Depends(get_current_account)):
    conn = _db()
    rows = conn.execute("""SELECT id, domain, severity, code, data, created_at, is_read FROM eye_alerts
                            WHERE account_id=? ORDER BY created_at DESC LIMIT 100""", (account["id"],)).fetchall()
    conn.close()
    return {"alerts": [{"id": r[0], "domain": r[1], "severity": r[2], "code": r[3],
                         "data": json.loads(r[4]), "created_at": r[5], "is_read": bool(r[6])} for r in rows]}


@app.post("/api/alerts/{alert_id}/read")
def mark_alert_read(alert_id: int, account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("UPDATE eye_alerts SET is_read=1 WHERE id=? AND account_id=?", (alert_id, account["id"]))
    conn.commit(); conn.close()
    return {"id": alert_id, "is_read": True}


@app.post("/api/alerts/mark-all-read")
def mark_all_alerts_read(account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("UPDATE eye_alerts SET is_read=1 WHERE account_id=?", (account["id"],))
    conn.commit(); conn.close()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Asset & software CVE inventory — the "internal, no-agent" visibility
# option: a self-reported list of what's actually running (office hardware,
# OS versions, software), vetted against the same NVD data domains use.
# ---------------------------------------------------------------------------
COMMON_ASSET_LABELS = [
    "Office Firewall", "Office Router", "Office Wi-Fi Access Point", "VPN Gateway",
    "File Server", "Email Server", "Backup Server", "Domain Controller",
    "Reception PC", "Employee Laptop", "Employee Desktop", "Point of Sale System",
    "Printer / Scanner", "Security Camera / NVR", "Guest Wi-Fi",
]


@app.get("/api/asset-catalog")
def asset_catalog():
    """The known, CVE-trackable products, grouped for a dropdown, plus a
    starter list of common asset labels and which products are relevant to
    each one. Either can be overridden with a custom typed value — this
    list is just a head start, not a restriction."""
    return {"categories": techstack.CPE_CATEGORIES, "common_labels": COMMON_ASSET_LABELS,
            "label_product_map": techstack.LABEL_TO_PRODUCTS}


class AssetCreate(BaseModel):
    label: str
    tech_key: Optional[str] = None
    version: Optional[str] = None


@app.post("/api/assets")
def add_asset(req: AssetCreate, account: dict = Depends(get_current_account)):
    if not req.label.strip():
        raise HTTPException(400, "Give this asset a label, e.g. 'Office firewall' or 'Reception PC'.")
    conn = _db()
    conn.execute("INSERT INTO assets (account_id, label, tech_key, version, created_at) VALUES (?,?,?,?,?)",
                 (account["id"], req.label.strip(), req.tech_key, req.version, datetime.datetime.utcnow().isoformat()))
    asset_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    return {"id": asset_id, "label": req.label.strip(), "tech_key": req.tech_key, "version": req.version}


@app.get("/api/assets")
def list_assets(account: dict = Depends(get_current_account)):
    conn = _db()
    rows = conn.execute("""SELECT id, label, tech_key, version, last_checked_at, cached_cves
                            FROM assets WHERE account_id=? ORDER BY created_at ASC""", (account["id"],)).fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r[0], "label": r[1], "tech_key": r[2], "version": r[3],
            "last_checked_at": r[4], "cves": json.loads(r[5]) if r[5] else None,
            "trackable": r[2] in techstack.CPE_MAP,
        })
    return {"assets": out}


@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: int, account: dict = Depends(get_current_account)):
    conn = _db()
    conn.execute("DELETE FROM assets WHERE id=? AND account_id=?", (asset_id, account["id"]))
    conn.commit(); conn.close()
    return {"deleted": asset_id}


@app.post("/api/assets/{asset_id}/check")
def check_asset(asset_id: int, account: dict = Depends(get_current_account)):
    conn = _db()
    row = conn.execute("SELECT label, tech_key, version FROM assets WHERE id=? AND account_id=?",
                        (asset_id, account["id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "No such asset.")
    label, tech_key, version = row

    if not tech_key or tech_key not in techstack.CPE_MAP:
        conn.close()
        raise HTTPException(400, "This product isn't in the trackable catalog yet — recorded for inventory, but no automatic CVE matching available.")
    if not version or not version.strip():
        conn.close()
        raise HTTPException(400, "Add a version number to check for known vulnerabilities.")

    cves = techstack.lookup_cves(tech_key, version.strip())
    checked_at = datetime.datetime.utcnow().isoformat()
    conn.execute("UPDATE assets SET last_checked_at=?, cached_cves=? WHERE id=?",
                 (checked_at, json.dumps(cves), asset_id))
    conn.commit(); conn.close()
    return {"id": asset_id, "label": label, "cves": cves, "last_checked_at": checked_at}


@app.post("/api/assets/check-all")
def check_all_assets(account: dict = Depends(get_current_account)):
    conn = _db()
    rows = conn.execute("SELECT id, tech_key, version FROM assets WHERE account_id=?", (account["id"],)).fetchall()
    conn.close()
    checked = 0
    for asset_id, tech_key, version in rows:
        if tech_key in techstack.CPE_MAP and version and version.strip():
            cves = techstack.lookup_cves(tech_key, version.strip())
            conn = _db()
            conn.execute("UPDATE assets SET last_checked_at=?, cached_cves=? WHERE id=?",
                         (datetime.datetime.utcnow().isoformat(), json.dumps(cves), asset_id))
            conn.commit(); conn.close()
            checked += 1
    return {"checked": checked, "total": len(rows)}
