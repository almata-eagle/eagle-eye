"""
Eagle Talon — Technology & CVE Correlation
============================================
Two-stage pipeline, deliberately kept as two separate concerns:

  1. Fingerprint technologies from the homepage response we already fetched
     for header-checking (Server/X-Powered-By headers, HTML generator tags,
     script filenames, cookie names) — the same passive technique
     Wappalyzer's open ruleset uses, just a compact hand-built subset here.

  2. Map (technology, version) -> known CVEs via the NVD (National
     Vulnerability Database) REST API using CPE identifiers. This is kept
     separate from fingerprinting so it can be swapped/extended (e.g. to
     OSV.dev for open-source package ecosystems) without touching detection.

Honesty built into the output on purpose: a version string is a *signal*,
not proof of an unpatched vulnerability — vendors routinely backport fixes
without bumping the version number. Findings are worded accordingly.
"""
import os
import re
import time
import threading

import requests

TIMEOUT = 6
HEADERS = {"User-Agent": "EagleTalon-ASM-Prototype/0.1 (+passive recon)"}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional — raises the rate limit 5/30s -> 50/30s

# ---------------------------------------------------------------------------
# Stage 1: passive technology fingerprinting
# ---------------------------------------------------------------------------
# Each rule: (technology name, where to look, regex with a version capture group
# or None if the tech has no meaningful version to extract)
TECH_SIGNATURES = [
    ("nginx",          "header:Server",       r"nginx/([\d.]+)"),
    ("Apache",         "header:Server",       r"Apache/([\d.]+)"),
    ("Microsoft-IIS",  "header:Server",       r"Microsoft-IIS/([\d.]+)"),
    ("PHP",            "header:X-Powered-By", r"PHP/([\d.]+)"),
    ("OpenSSL",        "header:Server",       r"OpenSSL/([\d.]+)"),
    ("WordPress",      "html",                r'<meta name="generator" content="WordPress ([\d.]+)'),
    ("Drupal",         "html",                r'content="Drupal ([\d.]+)'),
    ("Joomla",         "html",                r'content="Joomla! ([\d.]+)'),
    ("jQuery",         "html",                r'jquery[/-]([\d.]+)(?:\.min)?\.js'),
    ("Bootstrap",      "html",                r'bootstrap[/-]([\d.]+)(?:\.min)?\.(?:css|js)'),
    ("React",          "html",                r'react(?:-dom)?[.-]([\d.]+)(?:\.min)?\.js'),
    ("Log4j",          "html",                r'log4j[/-]([\d.]+)'),
    ("cloudflare",     "header:Server",       r"(cloudflare)"),
]

COOKIE_HINTS = [
    ("PHPSESSID", "PHP", None),
    ("JSESSIONID", "Java/JSP", None),
    ("wordpress_logged_in", "WordPress", None),
    ("CFID", "ColdFusion", None),
]


def detect_technologies(resp) -> list[dict]:
    """resp is a requests.Response (or None) from fetch_homepage(). Returns a
    list of {name, version, evidence} — version is None when the tech was
    detected but no version string was recoverable from this response."""
    if resp is None:
        return []

    findings = []
    seen = set()
    server_header = resp.headers.get("Server", "") or ""
    powered_by = resp.headers.get("X-Powered-By", "") or ""
    try:
        body = resp.text[:200_000]  # cap — we only need the <head> region typically
    except Exception:
        body = ""

    for name, source, pattern in TECH_SIGNATURES:
        haystack = {
            "header:Server": server_header,
            "header:X-Powered-By": powered_by,
            "html": body,
        }.get(source, "")
        if not haystack:
            continue
        m = re.search(pattern, haystack, re.IGNORECASE)
        if m and name not in seen:
            version = m.group(1) if m.groups() else None
            findings.append({"name": name, "version": version, "evidence": source})
            seen.add(name)

    for cookie_name, tech, _ in COOKIE_HINTS:
        if tech in seen:
            continue
        set_cookie = resp.headers.get("Set-Cookie", "") or ""
        if cookie_name.lower() in set_cookie.lower():
            findings.append({"name": tech, "version": None, "evidence": "cookie"})
            seen.add(tech)

    return findings


# ---------------------------------------------------------------------------
# Stage 2: technology -> CVE correlation via NVD
# ---------------------------------------------------------------------------
CPE_MAP = {
    # display name -> (cpe vendor, cpe product)
    "nginx": ("nginx", "nginx"),
    "Apache": ("apache", "http_server"),
    "Microsoft-IIS": ("microsoft", "internet_information_server"),
    "PHP": ("php", "php"),
    "OpenSSL": ("openssl", "openssl"),
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", "joomla%21"),
    "jQuery": ("jquery", "jquery"),
    "Bootstrap": ("getbootstrap", "bootstrap"),
    "React": ("facebook", "react"),
    "Log4j": ("apache", "log4j"),
}

_cve_cache: dict[tuple, list] = {}
_cache_lock = threading.Lock()

# Simple sliding-window self-throttle so we never exceed NVD's public rate limit.
_call_times: list[float] = []
_rate_lock = threading.Lock()
_MAX_CALLS = 45 if NVD_API_KEY else 4   # small safety margin under 50/30s and 5/30s
_WINDOW_SEC = 30


def _throttle():
    with _rate_lock:
        now = time.time()
        while _call_times and now - _call_times[0] > _WINDOW_SEC:
            _call_times.pop(0)
        if len(_call_times) >= _MAX_CALLS:
            sleep_for = _WINDOW_SEC - (now - _call_times[0]) + 0.1
            time.sleep(max(0, sleep_for))
        _call_times.append(time.time())


def lookup_cves(tech_name: str, version: str, max_results: int = 5) -> list[dict]:
    """Returns [{cve_id, summary, severity, score}], sorted worst-first.
    Cached by (tech, version) — matters a lot once scanning many domains that
    share the same common stack versions.

    Uses NVD's virtualMatchString rather than cpeName: cpeName requires the
    exact version to be individually registered in NVD's CPE dictionary,
    which is sparse for most products' minor/patch versions and silently
    returns zero results even when the version falls inside a real CVE's
    vulnerable range. virtualMatchString matches against those ranges
    directly (versionStartIncluding/versionEndExcluding etc. in each CVE's
    configurations), which is what actually finds real-world hits."""
    if not version or tech_name not in CPE_MAP:
        return []

    key = (tech_name, version)
    with _cache_lock:
        if key in _cve_cache:
            return _cve_cache[key]

    vendor, product = CPE_MAP[tech_name]
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    req_headers = dict(HEADERS)
    if NVD_API_KEY:
        req_headers["apiKey"] = NVD_API_KEY

    def _query(params: dict):
        _throttle()
        return requests.get(NVD_API, params=params, timeout=15, headers=req_headers)

    out = []
    debug_note = None
    try:
        resp = _query({"virtualMatchString": cpe, "resultsPerPage": max_results})
        if resp.status_code == 200:
            out = _parse_nvd_response(resp.json())
            if not out:
                debug_note = "no CVEs matched this version range (query succeeded)"
        elif resp.status_code == 404:
            # some NVD deployments reject virtualMatchString with unmapped products;
            # fall back to a keyword search on product name + version as a second attempt
            resp2 = _query({"keywordSearch": f"{product} {version}", "resultsPerPage": max_results})
            if resp2.status_code == 200:
                out = _parse_nvd_response(resp2.json())
                debug_note = "used keyword-search fallback"
            else:
                debug_note = f"virtualMatchString 404, keyword fallback also failed: HTTP {resp2.status_code}"
        else:
            debug_note = f"NVD returned HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        debug_note = f"request failed: {e}"

    with _cache_lock:
        _cve_cache[key] = out
        if debug_note:
            _last_debug[key] = debug_note
    return out


def _parse_nvd_response(data: dict) -> list[dict]:
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        severity, score = None, None
        metrics = cve.get("metrics", {})
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mkey in metrics and metrics[mkey]:
                m = metrics[mkey][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = m.get("baseSeverity") or cvss.get("baseSeverity")
                break
        out.append({
            "cve_id": cve_id,
            "summary": (summary[:220] + "…") if len(summary) > 220 else summary,
            "severity": (severity or "UNKNOWN").upper(),
            "score": score,
        })
    out.sort(key=lambda c: -(c["score"] or 0))
    return out


_last_debug: dict[tuple, str] = {}  # (tech,version) -> human-readable reason, for /api/debug/cve-lookup


def debug_lookup(tech_name: str, version: str) -> dict:
    """Same lookup, but returns the diagnostic note too — for /api/debug/cve-lookup."""
    results = lookup_cves(tech_name, version)
    return {
        "tech": tech_name, "version": version, "results_count": len(results),
        "results": results, "note": _last_debug.get((tech_name, version)),
    }


def detect_and_correlate(resp) -> list[dict]:
    """Full pipeline: fingerprint, then attach any known CVEs per technology."""
    techs = detect_technologies(resp)
    for tech in techs:
        tech["cves"] = lookup_cves(tech["name"], tech["version"]) if tech["version"] else []
    return techs
