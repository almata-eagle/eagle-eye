"""
Eagle Talon — Scan Engine
==========================
Passive/OSINT-only attack-surface reconnaissance for a single domain.
No intrusive scanning (no port sweeps, no exploitation, no auth bypass attempts) —
everything here is public record lookups: DNS, certificate transparency, TLS
handshake metadata, published security headers, and RDAP registration data.

This keeps the tool legally safe to run against third-party domains (suppliers,
sellers, insureds) without needing authorization, which matters a lot for the
ASM/supply-chain/insurance use case.
"""
import socket
import ssl
import time
import datetime
import concurrent.futures as cf
from dataclasses import dataclass, field, asdict
from typing import Optional

import dns.resolver
import requests
import techstack

TIMEOUT = 6
HEADERS = {"User-Agent": "EagleTalon-ASM-Prototype/0.1 (+passive recon)"}


# ---------------------------------------------------------------------------
# Individual checks — each is independent and fails soft (returns partial data
# + an "error" note rather than throwing), so one dead subsystem never kills
# the whole scan.
# ---------------------------------------------------------------------------

def check_dns(domain: str) -> dict:
    out = {"a": [], "mx": [], "ns": [], "txt": [], "error": None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT
    try:
        for rtype, key in [("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")]:
            try:
                answers = resolver.resolve(domain, rtype)
                out[key] = [str(r.to_text()) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                out["error"] = f"{rtype} lookup failed: {e}"
    except Exception as e:
        out["error"] = str(e)
    return out


def check_email_security(domain: str, txt_records: list[str]) -> dict:
    """SPF / DMARC / DKIM presence & basic policy strength — this is the
    single highest-value cheap signal for phishing/BEC exposure."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT

    spf = next((t for t in txt_records if "v=spf1" in t.lower()), None)

    dmarc_record, dmarc_policy = None, None
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if "v=dmarc1" in txt.lower():
                dmarc_record = txt
                for tag in txt.split(";"):
                    tag = tag.strip()
                    if tag.lower().startswith("p="):
                        dmarc_policy = tag.split("=", 1)[1].strip().lower()
    except Exception:
        pass

    # DKIM has no fixed selector; probe the common defaults. A miss here is
    # inconclusive (not proof DKIM is absent) so we label it as such.
    dkim_selectors_found = []
    for selector in ["default", "selector1", "selector2", "google", "k1", "mandrill", "mail"]:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_selectors_found.append(selector)
        except Exception:
            continue

    return {
        "spf_present": spf is not None,
        "spf_record": spf,
        "dmarc_present": dmarc_record is not None,
        "dmarc_policy": dmarc_policy,  # none | quarantine | reject
        "dkim_selectors_found": dkim_selectors_found,
        "dkim_probe_note": "Probed common selectors only — absence is not conclusive.",
    }


def check_tls(domain: str) -> dict:
    out = {"connected": False, "protocol": None, "issuer": None, "expires": None,
           "days_to_expiry": None, "self_signed": False, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                out["connected"] = True
                out["protocol"] = ssock.version()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                expires_raw = cert.get("notAfter")
                if expires_raw:
                    exp = datetime.datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z")
                    out["expires"] = exp.isoformat()
                    out["days_to_expiry"] = (exp - datetime.datetime.utcnow()).days
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"certificate not trusted: {e}"
        out["self_signed"] = "self-signed" in str(e).lower() or "self signed" in str(e).lower()
    except Exception as e:
        out["error"] = str(e)
    return out


def fetch_homepage(domain: str):
    """Single homepage fetch shared by header-checking and tech fingerprinting,
    so we don't hit the target twice for what's conceptually one request."""
    last_err = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=TIMEOUT,
                                 headers=HEADERS, allow_redirects=True)
            return resp
        except Exception as e:
            last_err = str(e)
            continue
    return None


def check_http_headers(resp) -> dict:
    out = {"reachable": False, "status": None, "server": None, "headers_present": [],
           "headers_missing": [], "error": None}
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Permissions-Policy",
    ]
    if resp is None:
        out["error"] = "could not connect over HTTP(S)"
        return out
    out["reachable"] = True
    out["status"] = resp.status_code
    out["server"] = resp.headers.get("Server")
    present = [h for h in security_headers if h in resp.headers]
    out["headers_present"] = present
    out["headers_missing"] = [h for h in security_headers if h not in present]
    return out


def check_subdomains(domain: str, limit: int = 200) -> dict:
    """Certificate-transparency log lookup via crt.sh — the standard passive
    subdomain-enumeration technique; no traffic ever touches the target."""
    out = {"count": 0, "sample": [], "error": None}
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=TIMEOUT + 4,
                             headers=HEADERS)
        if resp.status_code == 200 and resp.text.strip():
            rows = resp.json()
            names = set()
            for row in rows:
                for name in row.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name:
                        names.add(name)
            out["count"] = len(names)
            out["sample"] = sorted(names)[:limit]
        else:
            out["error"] = f"crt.sh returned {resp.status_code}"
    except Exception as e:
        out["error"] = str(e)
    return out


def check_rdap(domain: str) -> dict:
    """RDAP is the modern, structured successor to WHOIS — HTTPS based, so it
    works cleanly through normal egress rules unlike raw WHOIS (port 43)."""
    out = {"registrar": None, "created": None, "age_days": None, "error": None}
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    created = event.get("eventDate")
                    out["created"] = created
                    try:
                        created_dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                        out["age_days"] = (datetime.datetime.now(datetime.timezone.utc) - created_dt).days
                    except Exception:
                        pass
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field_ in vcard:
                        if field_[0] == "fn":
                            out["registrar"] = field_[3]
        else:
            out["error"] = f"rdap.org returned {resp.status_code}"
    except Exception as e:
        out["error"] = str(e)
    return out


def check_threat_intel(domain: str) -> dict:
    """Threat intel enrichment, kept 'smart' rather than a raw feed dump:
    we only surface a signal when there's an actual correlated hit, and we
    explain what it means rather than just listing indicators.

    Uses abuse.ch URLhaus's free, keyless host-lookup API — checks whether
    this exact host has been reported distributing malware. This is
    deliberately conservative (a real, sourced hit) rather than heuristic
    guessing, which matters when the score feeds a business decision.
    """
    out = {"checked": False, "malicious_host_reports": 0, "recent_threats": [], "error": None}
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                              data={"host": domain}, timeout=TIMEOUT, headers=HEADERS)
        out["checked"] = True
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                urls = data.get("urls", []) or []
                out["malicious_host_reports"] = len(urls)
                out["recent_threats"] = [
                    {"threat": u.get("threat"), "date_added": u.get("date_added"),
                     "status": u.get("url_status")}
                    for u in urls[:5]
                ]
        else:
            out["error"] = f"urlhaus returned {resp.status_code}"
    except Exception as e:
        out["error"] = str(e)
        out["checked"] = False
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class CategoryScore:
    code: str            # stable key for i18n, e.g. "email_security"
    name: str            # English display name (fallback)
    score: int          # 0 (worst) – 100 (best)
    weight: float
    findings: list = field(default_factory=list)  # list of {code, en, params}


def _f(code: str, en: str, **params) -> dict:
    """Build a structured finding: a stable code + params for translation,
    plus the pre-rendered English string as a fallback/default."""
    return {"code": code, "en": en, "params": params}


def score_threat_intel(ti: dict) -> CategoryScore:
    score, findings = 100, []
    n = ti.get("malicious_host_reports", 0)
    if ti.get("checked") and n > 0:
        score -= min(80, 25 + n * 8)
        findings.append(_f("urlhaus_hit",
                            f"This host has {n} reported malware-hosting URL(s) on record (URLhaus).", count=n))
    return CategoryScore("threat_intel", "Threat Intelligence", max(score, 0), 0.15, findings)


SEVERITY_DEDUCT = {"CRITICAL": 35, "HIGH": 22, "MEDIUM": 10, "LOW": 4, "UNKNOWN": 8}


def score_cve_exposure(technologies: list) -> CategoryScore:
    """technologies: output of techstack.detect_and_correlate(). Deliberately
    worded as a signal to verify, not a confirmed-vulnerable claim — see
    module docstring in techstack.py."""
    score, findings = 100, []
    for tech in technologies:
        for cve in tech.get("cves", []):
            deduct = SEVERITY_DEDUCT.get(cve.get("severity", "UNKNOWN"), 8)
            score -= deduct
            findings.append(_f(
                "cve_detected",
                f"{tech['name']} {tech['version']}: {cve['cve_id']} ({cve.get('severity','UNKNOWN')}) — {cve['summary']}",
                tech=tech["name"], version=tech["version"], cve_id=cve["cve_id"],
                severity=cve.get("severity", "UNKNOWN"), summary=cve["summary"],
            ))
    return CategoryScore("cve_exposure", "Known Vulnerabilities", max(score, 0), 0.2, findings[:8])


def score_email_security(email: dict) -> CategoryScore:
    score, findings = 100, []
    if not email["spf_present"]:
        score -= 35
        findings.append(_f("no_spf", "No SPF record — domain can be spoofed in the From/Return-Path."))
    if not email["dmarc_present"]:
        score -= 35
        findings.append(_f("no_dmarc", "No DMARC record — spoofed mail has no enforcement path."))
    elif email["dmarc_policy"] in (None, "none"):
        score -= 15
        findings.append(_f("dmarc_none", "DMARC policy is 'none' — monitoring only, not enforced."))
    if not email["dkim_selectors_found"]:
        score -= 10
        findings.append(_f("no_dkim", "No DKIM selector found among common defaults (probe is best-effort)."))
    return CategoryScore("email_security", "Email Security", max(score, 0), 0.25, findings)


def score_tls(tls: dict) -> CategoryScore:
    score, findings = 100, []
    if not tls["connected"]:
        score -= 50
        findings.append(_f("tls_failed", f"TLS handshake failed: {tls['error']}", error=tls["error"]))
    else:
        if tls.get("self_signed"):
            score -= 40
            findings.append(_f("self_signed", "Certificate is self-signed or otherwise untrusted."))
        if tls.get("days_to_expiry") is not None:
            days = tls["days_to_expiry"]
            if days < 0:
                score -= 50
                findings.append(_f("cert_expired", "Certificate has already expired."))
            elif days < 14:
                score -= 25
                findings.append(_f("cert_expiring", f"Certificate expires in {days} days.", days=days))
            elif days < 30:
                score -= 10
                findings.append(_f("cert_expiring", f"Certificate expires in {days} days.", days=days))
        if tls.get("protocol") in ("TLSv1", "TLSv1.1"):
            score -= 30
            findings.append(_f("legacy_tls", f"Negotiated legacy protocol {tls['protocol']}.",
                                protocol=tls["protocol"]))
    return CategoryScore("tls", "TLS / Certificates", max(score, 0), 0.2, findings)


def score_web_headers(http: dict) -> CategoryScore:
    score, findings = 100, []
    if not http["reachable"]:
        return CategoryScore("web_hardening", "Web Hardening", 50, 0.15,
                              [_f("unreachable", "Site not reachable over HTTP(S) — unscored.")])
    for h in http["headers_missing"]:
        score -= 10
    if http["headers_missing"]:
        joined = ", ".join(http["headers_missing"])
        findings.append(_f("missing_headers", f"Missing security headers: {joined}.",
                            headers=http["headers_missing"]))
    return CategoryScore("web_hardening", "Web Hardening", max(score, 0), 0.15, findings)


def score_exposure(subdomains: dict, dns_: dict) -> CategoryScore:
    score, findings = 100, []
    count = subdomains.get("count", 0)
    if count > 200:
        score -= 30
        findings.append(_f("large_surface", f"{count} certificate-visible subdomains — large discoverable surface.",
                            count=count))
    elif count > 50:
        score -= 15
        findings.append(_f("some_surface", f"{count} certificate-visible subdomains.", count=count))
    if not dns_.get("mx"):
        findings.append(_f("no_mx", "No MX records found (may be intentional)."))
    return CategoryScore("exposure", "Exposure Surface", max(score, 0), 0.2, findings)


def score_reputation(rdap: dict) -> CategoryScore:
    score, findings = 100, []
    age = rdap.get("age_days")
    if age is not None:
        if age < 90:
            score -= 40
            findings.append(_f("very_new_domain",
                                f"Domain registered only {age} days ago — common fraud/phishing signal.", age=age))
        elif age < 365:
            score -= 15
            findings.append(_f("new_domain", f"Domain is under a year old ({age} days).", age=age))
    else:
        score -= 5
        findings.append(_f("age_unknown", "Registration age unavailable via RDAP."))
    return CategoryScore("reputation", "Domain Reputation", max(score, 0), 0.2, findings)


def tier_for_score(score: int) -> str:
    if score >= 80:
        return "clear"
    if score >= 60:
        return "watch"
    if score >= 35:
        return "high"
    return "critical"


def scan_domain(domain: str) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    started = time.time()

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        f_dns = ex.submit(check_dns, domain)
        f_tls = ex.submit(check_tls, domain)
        f_home = ex.submit(fetch_homepage, domain)
        f_subs = ex.submit(check_subdomains, domain)
        f_rdap = ex.submit(check_rdap, domain)
        f_ti = ex.submit(check_threat_intel, domain)

        dns_ = f_dns.result()
        tls = f_tls.result()
        home_resp = f_home.result()
        subs = f_subs.result()
        rdap = f_rdap.result()
        ti = f_ti.result()

    http = check_http_headers(home_resp)
    technologies = techstack.detect_and_correlate(home_resp)
    email = check_email_security(domain, dns_.get("txt", []))

    categories = [
        score_email_security(email),
        score_tls(tls),
        score_web_headers(http),
        score_exposure(subs, dns_),
        score_reputation(rdap),
        score_threat_intel(ti),
        score_cve_exposure(technologies),
    ]
    total_weight = sum(c.weight for c in categories)
    overall = round(sum(c.score * c.weight for c in categories) / total_weight)

    return {
        "domain": domain,
        "overall_score": overall,
        "tier": tier_for_score(overall),
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "duration_sec": round(time.time() - started, 2),
        "categories": [asdict(c) for c in categories],
        "technologies": technologies,
        "raw": {
            "dns": dns_, "email": email, "tls": tls, "http": http,
            "subdomains": subs, "rdap": rdap, "threat_intel": ti,
        },
    }
