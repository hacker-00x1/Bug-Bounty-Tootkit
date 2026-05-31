"""
endpoint_scanner.py — Test every crawled URL and form for injection bugs.

The core vuln checks in vulns.py only probe the homepage with generic param names.
This module receives the crawler's real discovered URLs and forms, extracts the
actual parameters the app uses, and injects XSS / SQLi / open-redirect / LFI
payloads into them. CORS is also tested per-endpoint.

Finding format matches the rest of the tool so reporter.py needs no changes.
"""

import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ── Severity constants ───────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

# ── Params that suggest path / file inclusion ────────────────────────────────
_LFI_PARAM_HINTS = frozenset([
    "file", "page", "include", "path", "template", "view",
    "doc", "document", "load", "dir", "folder", "img", "image",
    "filename", "filepath", "f", "p",
])

# ── Params that suggest redirect destination ─────────────────────────────────
_REDIRECT_PARAM_HINTS = frozenset([
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnurl", "returnto", "goto", "target", "redir", "destination",
    "r", "u", "continue", "forward", "location", "back",
])

# ── XSS payloads ─────────────────────────────────────────────────────────────
_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
]

# ── SQLi error-triggering payloads ───────────────────────────────────────────
_SQLI_PAYLOADS = ["'", '"', "' OR '1'='1"]

_SQLI_ERRORS = re.compile(
    r"you have an error in your sql syntax"
    r"|warning: mysql"
    r"|unclosed quotation mark"
    r"|quoted string not properly terminated"
    r"|pg_query\(\): query failed"
    r"|ORA-\d+"
    r"|microsoft sql server"
    r"|sqlite_exception"
    r"|syntax error.*near"
    r"|PDOException",
    re.IGNORECASE,
)

# ── Open-redirect payloads ────────────────────────────────────────────────────
_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com"]

# ── LFI payloads + confirmation strings ──────────────────────────────────────
_LFI_PAYLOADS    = ["../../etc/passwd", "../../../etc/passwd", "%2e%2e%2fetc%2fpasswd"]
_LFI_INDICATORS  = ["root:x:0:0", "daemon:", "nobody:", "/bin/bash", "/bin/sh"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ua() -> dict:
    return {"User-Agent": "BugBountyTool/1.0"}


def _fetch(url: str, timeout: int, method: str = "GET",
           post_data: Optional[bytes] = None) -> Optional[dict]:
    """Minimal fetch — returns {status, body, content_type, headers, location}."""
    try:
        req = urllib.request.Request(url, data=post_data, headers=_ua(), method=method)
        opener = urllib.request.build_opener(urllib.request.BaseHandler())
        try:
            with opener.open(req, timeout=timeout) as r:
                raw = r.read(65536)
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                return {
                    "status": r.status,
                    "body": raw.decode("utf-8", errors="replace"),
                    "content_type": hdrs.get("content-type", ""),
                    "headers": hdrs,
                    "location": hdrs.get("location", ""),
                }
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            raw  = e.read(16384)
            return {
                "status": e.code,
                "body": raw.decode("utf-8", errors="replace"),
                "content_type": hdrs.get("content-type", ""),
                "headers": hdrs,
                "location": hdrs.get("location", ""),
            }
    except Exception:
        return None


def _url_base(url: str) -> str:
    """Return scheme+netloc+path without query string."""
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(query="", fragment=""))


def _inject_get_param(url: str, param: str, payload: str) -> str:
    """Replace `param` value in `url`'s query string with `payload`."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _make_post_body(params: list[str], payload: str, target_param: str) -> bytes:
    """Build URL-encoded POST body with `target_param` set to `payload`."""
    data = {p: (payload if p == target_param else "test") for p in params}
    return urllib.parse.urlencode(data).encode()


# ── Per-finding checkers ──────────────────────────────────────────────────────

def _check_xss(url: str, param: str, payload: str, timeout: int,
               method: str = "GET", post_data: Optional[bytes] = None) -> Optional[dict]:
    res = _fetch(url, timeout, method=method, post_data=post_data)
    if not res:
        return None
    ct = res["content_type"].lower()
    if ct and "text/html" not in ct:
        return None
    body = res["body"]
    if payload not in body:
        return None
    encoded = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;"),
        payload.replace("'", "&#x27;"),
    ]
    if any(enc in body for enc in encoded) and payload not in body:
        return None
    return {
        "type": "Reflected XSS",
        "severity": HIGH,
        "description": (
            f"Reflected XSS via {method} ?{param}= at {_url_base(url)} — "
            "payload echoed unencoded in an HTML response"
        ),
        "url": url,
        "param": param,
        "payload": payload,
        "method": method,
        "recommendation": "HTML-encode all user input before reflecting in responses. Apply a strict Content-Security-Policy.",
        "h1_note": (
            "Confirm execution in a real browser before submitting. "
            "Check the reflection is in an executable context (not inside a JS string or HTML comment). "
            "Alert-based PoC is acceptable on H1."
        ),
    }


def _check_sqli(url: str, param: str, payload: str, timeout: int,
                method: str = "GET", post_data: Optional[bytes] = None) -> Optional[dict]:
    res = _fetch(url, timeout, method=method, post_data=post_data)
    if not res:
        return None
    if _SQLI_ERRORS.search(res["body"]):
        return {
            "type": "SQL Injection (Error-Based)",
            "severity": CRITICAL,
            "description": (
                f"SQL error triggered via {method} ?{param}= at {_url_base(url)}"
            ),
            "url": url,
            "param": param,
            "payload": payload,
            "method": method,
            "recommendation": "Use parameterized queries / prepared statements for all DB queries.",
            "h1_note": (
                "This IS a valid H1 CRITICAL. Include the full error message in your report. "
                "Try to escalate to data extraction (UNION-based or blind time-based) "
                "to maximize impact and payout."
            ),
        }
    return None


def _check_redirect(url: str, param: str, payload: str, timeout: int) -> Optional[dict]:
    res = _fetch(url, timeout)
    if not res:
        return None
    loc = res.get("location", "").lower()
    if res["status"] in (301, 302, 303, 307, 308) and "evil.com" in loc:
        return {
            "type": "Open Redirect",
            "severity": MEDIUM,
            "description": (
                f"Open redirect via ?{param}= at {_url_base(url)} — "
                "server redirects to attacker-controlled domain"
            ),
            "url": url,
            "param": param,
            "payload": payload,
            "recommendation": "Validate redirect destinations against a strict allowlist.",
            "h1_note": (
                "Open redirect is MEDIUM on H1 when it can be used to steal OAuth tokens "
                "or aid phishing. For maximum payout, chain it with an OAuth flow "
                "(e.g., ?redirect_uri=https://evil.com). Standalone open redirects are LOW–MEDIUM."
            ),
        }
    return None


def _check_lfi(url: str, param: str, payload: str, timeout: int) -> Optional[dict]:
    res = _fetch(url, timeout)
    if not res:
        return None
    body = res["body"]
    if any(ind in body for ind in _LFI_INDICATORS):
        return {
            "type": "Local File Inclusion (LFI)",
            "severity": CRITICAL,
            "description": (
                f"LFI via ?{param}= at {_url_base(url)} — "
                "/etc/passwd content detected in response"
            ),
            "url": url,
            "param": param,
            "payload": payload,
            "recommendation": "Never pass user-supplied paths to file include/read functions. Use a whitelist of allowed files.",
            "h1_note": (
                "This is CRITICAL on H1. Escalate: try to read /proc/self/environ, "
                "application config files, SSH keys, or DB credentials. "
                "Include the file content snippet in your PoC."
            ),
        }
    return None


def _check_cors_endpoint(url: str, timeout: int) -> Optional[dict]:
    """Test a single endpoint for CORS origin reflection."""
    evil = "https://evil.com"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "BugBountyTool/1.0", "Origin": evil},
        )
        opener = urllib.request.build_opener(urllib.request.BaseHandler())
        try:
            with opener.open(req, timeout=timeout) as r:
                hdrs = {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower()
        if evil in acao and acac == "true":
            return {
                "type": "CORS Misconfiguration — Authenticated Origin Reflection",
                "severity": CRITICAL,
                "description": (
                    f"Endpoint {_url_base(url)} reflects arbitrary Origin in ACAO "
                    "AND sets Access-Control-Allow-Credentials: true. "
                    "Any site can make authenticated cross-origin requests and read responses."
                ),
                "url": url,
                "recommendation": "Validate Origin against a strict allowlist. Never reflect untrusted origins when ACAC=true.",
                "h1_note": (
                    "HIGH or CRITICAL on H1. Write a PoC page using fetch(url, {credentials:'include'}) "
                    "and dump the response body to confirm sensitive data leakage."
                ),
            }
        if evil in acao and acac != "true":
            return {
                "type": "CORS Misconfiguration — Origin Reflection",
                "severity": LOW,
                "description": (
                    f"Endpoint {_url_base(url)} reflects arbitrary Origin in ACAO "
                    "without credentials. Impact depends on response sensitivity."
                ),
                "url": url,
                "recommendation": "Validate Origin against an explicit allowlist.",
                "h1_note": (
                    "H1 acceptance depends on response contents. "
                    "If the endpoint returns sensitive data to anonymous users, report it. "
                    "If responses are already public, expect N/A."
                ),
            }
    except Exception:
        pass
    return None


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_crawled_endpoints(
    base_url:  str,
    all_urls:  list,
    all_forms: list,
    timeout:   int  = 6,
    max_urls:  int  = 60,
    max_forms: int  = 20,
    threads:   int  = 30,
) -> list[dict]:
    """
    Test every crawled URL and form for XSS, SQLi, open redirect, LFI, and CORS.

    Args:
        base_url:  The scan root (e.g. https://example.com)
        all_urls:  Full URLs discovered by the crawler (may include query strings)
        all_forms: Form dicts from crawler: {action, params, method}
        timeout:   Per-request timeout in seconds
        max_urls:  Max number of URLs to test (avoids scan timeout)
        max_forms: Max number of forms to test
        threads:   Worker thread count

    Returns:
        List of finding dicts compatible with the rest of the tool.
    """
    findings:  list[dict]  = []
    seen:      set[str]    = set()
    lock = threading.Lock()

    def _add(finding: Optional[dict]) -> None:
        if not finding:
            return
        key = (finding.get("type"), finding.get("param"), _url_base(finding.get("url", "")))
        with lock:
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    jobs: list = []

    # ── GET param jobs from crawled URLs ──────────────────────────────────────
    tested_cors: set[str] = set()

    urls_with_params = [
        u for u in all_urls
        if urllib.parse.urlparse(u).query
    ][:max_urls]

    for url in urls_with_params:
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params:
            continue

        base = _url_base(url)
        if base not in tested_cors:
            tested_cors.add(base)
            jobs.append(("cors", url, None, None, "GET", None))

        for param in params:
            param_lower = param.lower()

            for payload in _XSS_PAYLOADS[:2]:
                test_url = _inject_get_param(url, param, payload)
                jobs.append(("xss", test_url, param, payload, "GET", None))

            for payload in _SQLI_PAYLOADS[:2]:
                test_url = _inject_get_param(url, param, payload)
                jobs.append(("sqli", test_url, param, payload, "GET", None))

            if param_lower in _REDIRECT_PARAM_HINTS:
                for payload in _REDIRECT_PAYLOADS[:1]:
                    test_url = _inject_get_param(url, param, payload)
                    jobs.append(("redirect", test_url, param, payload, "GET", None))

            if param_lower in _LFI_PARAM_HINTS:
                for payload in _LFI_PAYLOADS[:2]:
                    test_url = _inject_get_param(url, param, payload)
                    jobs.append(("lfi", test_url, param, payload, "GET", None))

    # ── Form jobs ─────────────────────────────────────────────────────────────
    for form in all_forms[:max_forms]:
        action  = form.get("action", base_url)
        params  = form.get("params", [])
        method  = (form.get("method") or "GET").upper()
        if not params:
            continue

        if action not in tested_cors:
            tested_cors.add(action)
            jobs.append(("cors", action, None, None, "GET", None))

        for param in params:
            param_lower = param.lower()

            for payload in _XSS_PAYLOADS[:2]:
                if method == "POST":
                    body = _make_post_body(params, payload, param)
                    jobs.append(("xss", action, param, payload, "POST", body))
                else:
                    test_url = _inject_get_param(action, param, payload)
                    jobs.append(("xss", test_url, param, payload, "GET", None))

            for payload in _SQLI_PAYLOADS[:2]:
                if method == "POST":
                    body = _make_post_body(params, payload, param)
                    jobs.append(("sqli", action, param, payload, "POST", body))
                else:
                    test_url = _inject_get_param(action, param, payload)
                    jobs.append(("sqli", test_url, param, payload, "GET", None))

            if param_lower in _REDIRECT_PARAM_HINTS:
                payload = _REDIRECT_PAYLOADS[0]
                if method == "POST":
                    body = _make_post_body(params, payload, param)
                    jobs.append(("redirect", action, param, payload, "POST", body))
                else:
                    test_url = _inject_get_param(action, param, payload)
                    jobs.append(("redirect", test_url, param, payload, "GET", None))

            if param_lower in _LFI_PARAM_HINTS:
                payload = _LFI_PAYLOADS[0]
                if method == "POST":
                    body = _make_post_body(params, payload, param)
                    jobs.append(("lfi", action, param, payload, "POST", body))
                else:
                    test_url = _inject_get_param(action, param, payload)
                    jobs.append(("lfi", test_url, param, payload, "GET", None))

    if not jobs:
        return []

    # ── Dispatch all jobs in parallel ─────────────────────────────────────────
    def _run(job) -> None:
        check_type, url, param, payload, method, post_data = job
        try:
            if check_type == "cors":
                _add(_check_cors_endpoint(url, timeout))
            elif check_type == "xss":
                _add(_check_xss(url, param, payload, timeout, method, post_data))
            elif check_type == "sqli":
                _add(_check_sqli(url, param, payload, timeout, method, post_data))
            elif check_type == "redirect":
                _add(_check_redirect(url, param, payload, timeout))
            elif check_type == "lfi":
                _add(_check_lfi(url, param, payload, timeout))
        except Exception:
            pass

    w = min(threads, len(jobs))
    with ThreadPoolExecutor(max_workers=w) as pool:
        futs = [pool.submit(_run, j) for j in jobs]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass

    return findings
