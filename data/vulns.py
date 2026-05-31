'''
╭──────────────────────────────────────────────────────────────────────────────╮
│  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗ ██╗  
│  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚██╗██╔╝███║  
│  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║ ╚███╔╝  ██║  
│  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ██╔██╗  ██║  
│  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝██╔╝ ██╗ ██║  
│  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝  
│                                                                              
│    Bug Bounty Tool Kit  ─  Recon · Scan · Exploit · Report                  
╰── Only scan targets you own or have explicit written permission to test ─────╯
'''

import re
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from data.webfuzz import fetch_url


SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


def _http_redirects_to_https(base_url: str, timeout: int = 5) -> tuple[bool, str]:
    """Probe base_url over plain HTTP (no follow) and return (redirects_to_https, detail).

    Returns:
        (True,  detail) — HTTP redirects to HTTPS → HSTS finding is downgrade-worthy (INFO)
        (False, detail) — HTTP accessible directly → HSTS is a real finding (MEDIUM)
    """
    try:
        parsed   = urllib.parse.urlparse(base_url)
        http_url = urllib.parse.urlunparse(parsed._replace(scheme="http"))
        req = urllib.request.Request(http_url, headers={"User-Agent": "BugBountyTool/1.0"})
        opener = urllib.request.build_opener(urllib.request.BaseHandler())
        try:
            resp = opener.open(req, timeout=timeout)
            # Got a 2xx — HTTP is fully accessible without any redirect
            return False, f"HTTP {resp.status} — site is reachable over plain HTTP without redirecting to HTTPS"
        except urllib.error.HTTPError as e:
            loc = (e.headers.get("Location") or "").lower()
            if e.code in (301, 302, 303, 307, 308) and loc.startswith("https://"):
                return True, f"HTTP {e.code} → {e.headers.get('Location')} — site enforces HTTPS via redirect"
            # Non-redirect HTTP error (403, 404 etc.) — HTTP port is open
            return False, f"HTTP {e.code} — plain HTTP port is reachable (no HTTPS redirect)"
    except OSError:
        # Connection refused / timeout — port 80 likely closed; HSTS less critical
        return True, "Plain HTTP port appears closed or unreachable — HTTPS-only deployment"
    except Exception:
        return True, "Could not probe plain HTTP — assuming HTTPS-only deployment"


def check_security_headers(response: dict, base_url: str = "") -> list[dict]:
    issues = []
    headers = response.get("headers", {})

    # H1 severity reality: most programs treat missing headers as LOW/INFO.
    # HSTS is MEDIUM only when HTTP is reachable. CSP/XFO are LOW.
    # X-Content-Type-Options, Referrer-Policy, Permissions-Policy are INFO — H1 rarely accepts these.
    required_headers = {
        "strict-transport-security": {
            "severity": SEVERITY_MEDIUM,
            "description": "Missing Strict-Transport-Security (HSTS) header — site may be downgraded from HTTPS to HTTP by a MITM attacker",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "h1_note": "H1 accepts HSTS findings when the site is accessible over plain HTTP (verify with curl -I http://). If HTTPS auto-redirects to HTTPS, most programs won't pay.",
        },
        "content-security-policy": {
            "severity": SEVERITY_LOW,
            "description": "Missing Content-Security-Policy header — no browser-side XSS mitigation in place",
            "recommendation": "Implement a strict CSP: Content-Security-Policy: default-src 'self'",
            "h1_note": "H1 programs rarely pay for missing CSP alone. Only report alongside a confirmed XSS to show the absence of mitigation.",
        },
        "x-frame-options": {
            "severity": SEVERITY_LOW,
            "description": "Missing X-Frame-Options header — page could be embedded in a malicious iframe (clickjacking)",
            "recommendation": "Add: X-Frame-Options: DENY  or use Content-Security-Policy: frame-ancestors 'none'",
            "h1_note": "Clickjacking is only accepted by H1 if the framed page has a sensitive action (login, payment, settings change). Informational on static/public pages.",
        },
        "x-content-type-options": {
            "severity": SEVERITY_INFO,
            "description": "Missing X-Content-Type-Options header — browser may MIME-sniff responses",
            "recommendation": "Add: X-Content-Type-Options: nosniff",
            "h1_note": "Almost always out of scope on H1. Do not submit unless program explicitly lists this as in-scope.",
        },
        "referrer-policy": {
            "severity": SEVERITY_INFO,
            "description": "Missing Referrer-Policy header — Referer header may leak sensitive URL fragments to third parties",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "h1_note": "Rarely accepted by H1 programs. Skip unless program scope explicitly includes header hardening.",
        },
        "permissions-policy": {
            "severity": SEVERITY_INFO,
            "description": "Missing Permissions-Policy header — browser features (camera, mic, geolocation) not explicitly restricted",
            "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "h1_note": "Not accepted as a standalone finding on H1. Skip.",
        },
    }

    for header, info in required_headers.items():
        if header not in headers:
            sev   = info["severity"]
            desc  = info["description"]
            h1    = info.get("h1_note", "")
            url   = info.get("url", "")

            # ── HSTS: probe plain HTTP before reporting ────────────────────
            if header == "strict-transport-security" and base_url:
                redirects, probe_detail = _http_redirects_to_https(base_url)
                if redirects:
                    # HTTP → HTTPS redirect in place: browser never uses plain HTTP,
                    # so the missing HSTS header has no real attack surface.
                    sev  = SEVERITY_INFO
                    desc = (
                        "Missing Strict-Transport-Security (HSTS) header — "
                        "however, the server already redirects plain HTTP to HTTPS, "
                        "so the practical exposure is low."
                    )
                    h1   = (
                        f"Probe result: {probe_detail}. "
                        "Most H1 programs will N/A this because the HTTP→HTTPS redirect "
                        "already prevents downgrade attacks in practice. "
                        "Only report if the program specifically lists HSTS as in-scope."
                    )
                    url = base_url.replace("https://", "http://").split("/")[0] + "//"
                else:
                    # Plain HTTP is reachable — real attack surface, keep MEDIUM
                    desc = (
                        "Missing Strict-Transport-Security (HSTS) header AND plain HTTP "
                        "is accessible without redirect. A network attacker can strip HTTPS "
                        "and intercept traffic."
                    )
                    h1   = (
                        f"Probe result: {probe_detail}. "
                        "This IS a valid H1 finding — HTTP is reachable without HTTPS redirect. "
                        "Include `curl -I http://{domain}` output showing the 200/non-redirect "
                        "response in your PoC."
                    )
                    url = base_url

            # ── X-Frame-Options: check if CSP frame-ancestors already protects ──
            if header == "x-frame-options":
                csp_val = headers.get("content-security-policy", "")
                if "frame-ancestors" in csp_val.lower():
                    # CSP frame-ancestors is the modern replacement for XFO — page is protected
                    sev  = SEVERITY_INFO
                    desc = (
                        "X-Frame-Options header is absent, but Content-Security-Policy "
                        "includes a `frame-ancestors` directive which provides equivalent "
                        "(and stronger) clickjacking protection in modern browsers."
                    )
                    h1   = (
                        f"CSP frame-ancestors detected: `{csp_val[:120]}`. "
                        "Page is already framing-safe via CSP. Do NOT report as clickjacking — "
                        "this will be N/A'd by every H1 triage team."
                    )
                else:
                    # Neither XFO nor CSP frame-ancestors — page can be framed
                    # Only actionable on pages with sensitive user actions
                    desc = (
                        "Missing X-Frame-Options header and no CSP frame-ancestors directive. "
                        "Page can be embedded in a cross-origin iframe, enabling clickjacking attacks."
                    )
                    h1   = (
                        "Clickjacking is accepted by H1 ONLY on pages with sensitive actions "
                        "(login, payment confirmation, account settings, OAuth approve). "
                        "Build a PoC iframe page that loads the target URL and demonstrate "
                        "a user action being hijacked. Static/public pages will be N/A'd."
                    )

            issues.append({
                "type": "Missing Security Header",
                "header": header,
                "severity": sev,
                "description": desc,
                "recommendation": info["recommendation"],
                "h1_note": h1,
                **({"url": url} if url else {}),
            })

    if "server" in headers:
        server_val = headers["server"]
        version_match = re.search(r'[\d.]+', server_val)
        if version_match:
            issues.append({
                "type": "Server Version Disclosure",
                "header": "server",
                "severity": SEVERITY_INFO,
                "description": f"Server header reveals version: {server_val}",
                "recommendation": "Remove or genericize the Server header",
                "h1_note": "H1 programs almost never pay for version disclosure in headers. Only valuable as supporting evidence when chained with a known CVE for that version.",
            })

    if "x-powered-by" in headers:
        issues.append({
            "type": "Technology Disclosure",
            "header": "x-powered-by",
            "severity": SEVERITY_INFO,
            "description": f"X-Powered-By reveals technology: {headers['x-powered-by']}",
            "recommendation": "Remove X-Powered-By header",
            "h1_note": "Not accepted as a standalone finding on H1. Useful only as recon context when chaining with a framework-specific exploit.",
        })

    return issues


def check_cors(base_url: str, timeout: int = 5) -> list[dict]:
    issues = []
    malicious_origin = "https://evil.com"
    try:
        req = urllib.request.Request(base_url, headers={
            "Origin": malicious_origin,
            "User-Agent": "BugBountyTool/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            if acao == "*":
                # Wildcard ACAO: browsers block credentials (cookies/auth headers) with *, so
                # cross-origin requests to authenticated endpoints are NOT possible.
                # Impact is limited to reading unauthenticated public responses → INFO.
                issues.append({
                    "type": "CORS Misconfiguration",
                    "severity": SEVERITY_INFO,
                    "description": "Access-Control-Allow-Origin: * — any origin can read public (unauthenticated) responses. Credentials cannot be sent with a wildcard ACAO.",
                    "recommendation": "Restrict CORS to specific trusted origins if responses contain sensitive data even without authentication.",
                    "url": base_url,
                    "h1_note": "Wildcard CORS without credentials is INFO on H1. Browsers block cookies/auth headers when ACAO=*. Only report if the endpoint returns sensitive data to anonymous users AND you can demonstrate real impact.",
                })
            elif malicious_origin in acao:
                if acac.lower() == "true":
                    # Reflected origin + credentials=true: attacker can make authenticated
                    # cross-origin requests and read the response. This is CRITICAL.
                    issues.append({
                        "type": "CORS Misconfiguration — Authenticated Origin Reflection",
                        "severity": SEVERITY_CRITICAL,
                        "description": (
                            "Server reflects arbitrary attacker-controlled Origin in ACAO AND sets "
                            "Access-Control-Allow-Credentials: true. Any site can make authenticated "
                            "cross-origin requests on behalf of a logged-in user and read the response."
                        ),
                        "recommendation": "Validate Origin against a strict allowlist. Never reflect untrusted origins when ACAC=true.",
                        "url": base_url,
                        "origin_sent": malicious_origin,
                        "with_credentials": True,
                        "h1_note": "This is a HIGH or CRITICAL on H1. Write a PoC page that calls the endpoint with fetch(..., {credentials:'include'}) and dumps the response to confirm data leakage.",
                    })
                else:
                    # Reflected origin WITHOUT credentials: attacker can read unauthenticated
                    # responses cross-origin. Impact is LOW unless endpoint leaks sensitive data to
                    # anonymous users.
                    issues.append({
                        "type": "CORS Misconfiguration — Origin Reflection",
                        "severity": SEVERITY_LOW,
                        "description": (
                            "Server reflects the attacker-controlled Origin in ACAO but does NOT set "
                            "Access-Control-Allow-Credentials: true. Impact limited to reading responses "
                            "that are already publicly accessible."
                        ),
                        "recommendation": "Validate Origin against an explicit allowlist instead of reflecting the request Origin.",
                        "url": base_url,
                        "origin_sent": malicious_origin,
                        "with_credentials": False,
                        "h1_note": "H1 acceptance depends on what data the endpoint returns. If the response contains sensitive data accessible without a session cookie, this can be MEDIUM. If responses are public anyway, expect N/A or Informational.",
                    })
    except Exception:
        pass
    return issues


def check_open_redirect(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for open redirect — all param×payload combinations run in parallel."""
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "///evil.com",
    ]
    params = ["redirect", "url", "next", "return", "returnUrl", "returnTo",
              "redirect_uri", "goto", "target", "redir", "destination", "r", "u"]

    parsed = urllib.parse.urlparse(base_url)
    jobs: list[tuple[str, str, str]] = []  # (param, payload, test_url)
    for param in params:
        for payload in payloads[:2]:
            qs = urllib.parse.urlencode({param: payload})
            test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
            jobs.append((param, payload, test_url))

    found_params: set[str] = set()
    issues: list[dict] = []
    lock = __import__("threading").Lock()

    def _check(param: str, payload: str, test_url: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "BugBountyTool/1.0"})
            opener = urllib.request.build_opener(urllib.request.BaseHandler())
            try:
                with opener.open(req, timeout=timeout) as resp:
                    location = resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                location = e.headers.get("Location", "")
            if "evil.com" in location:
                return {
                    "type": "Open Redirect",
                    "severity": SEVERITY_MEDIUM,
                    "description": f"Open redirect via ?{param}= parameter",
                    "url": test_url,
                    "param": param,
                    "recommendation": "Validate redirect destinations against a whitelist",
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as executor:
        futures = {executor.submit(_check, p, pl, u): p for p, pl, u in jobs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                with lock:
                    param = result["param"]
                    if param not in found_params:
                        found_params.add(param)
                        issues.append(result)

    return issues


def check_xss(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for reflected XSS — all param×payload combinations run in parallel."""
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
    ]
    params = ["q", "search", "query", "s", "input", "name", "term", "id",
              "page", "msg", "text", "comment"]

    parsed = urllib.parse.urlparse(base_url)
    jobs: list[tuple[str, str, str]] = []
    for param in params:
        for payload in payloads[:2]:
            qs = urllib.parse.urlencode({param: payload})
            test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
            jobs.append((param, payload, test_url))

    found_params: set[str] = set()
    issues: list[dict] = []
    lock = __import__("threading").Lock()

    def _check(param: str, payload: str, test_url: str) -> Optional[dict]:
        try:
            result = fetch_url(test_url, timeout=timeout)
            if not result:
                return None
            # Only flag XSS on HTML responses — JSON/XML/text reflections do not execute
            content_type = (result.get("content_type") or result.get("headers", {}).get("content-type", "")).lower()
            if "text/html" not in content_type and content_type:
                return None
            body = result.get("body", "")
            if payload not in body:
                return None
            # Reject if the payload is HTML-encoded in the response (not a real XSS)
            encoded_variants = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace('"', "&quot;"),
                payload.replace("'", "&#x27;"),
            ]
            if any(enc in body for enc in encoded_variants) and payload not in body:
                return None
            return {
                "type": "Reflected XSS",
                "severity": SEVERITY_HIGH,
                "description": f"Reflected XSS via ?{param}= — payload echoed unencoded in an HTML response",
                "url": test_url,
                "param": param,
                "payload": payload,
                "recommendation": "HTML-encode all user input before reflecting it in responses. Apply a strict Content-Security-Policy.",
                "h1_note": "Confirm execution in a real browser before submitting. Check that the reflection is in an executable context (not inside a JS string literal or HTML comment). Alert-based PoC is acceptable on H1.",
            }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as executor:
        futures = {executor.submit(_check, p, pl, u): p for p, pl, u in jobs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                with lock:
                    param = result["param"]
                    if param not in found_params:
                        found_params.add(param)
                        issues.append(result)

    return issues


def check_sqli(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for SQL injection — all param×payload combinations run in parallel,
    returns immediately on first confirmed finding."""
    payloads = ["'", '"', "' OR '1'='1", "1 AND 1=1", "1; DROP TABLE users--"]
    error_patterns = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(\): query failed",
        r"ORA-\d+",
        r"microsoft sql server",
        r"sqlite_exception",
        r"syntax error.*near",
        r"PDOException",
    ]
    params = ["id", "user", "username", "product", "category", "order",
              "page", "sort", "q", "search"]

    parsed = urllib.parse.urlparse(base_url)
    jobs: list[tuple[str, str, str]] = []
    for param in params:
        for payload in payloads[:3]:
            qs = urllib.parse.urlencode({param: payload})
            test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
            jobs.append((param, payload, test_url))

    import threading
    stop_event = threading.Event()
    result_holder: list[dict] = []
    lock = threading.Lock()

    def _check(param: str, payload: str, test_url: str) -> None:
        if stop_event.is_set():
            return
        try:
            result = fetch_url(test_url, timeout=timeout)
            if result and not stop_event.is_set():
                body_lower = result.get("body", "").lower()
                for pattern in error_patterns:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        with lock:
                            if not stop_event.is_set():
                                stop_event.set()
                                result_holder.append({
                                    "type": "SQL Injection (Error-Based)",
                                    "severity": SEVERITY_CRITICAL,
                                    "description": f"SQL error triggered via ?{param}= — likely SQL injection point",
                                    "url": test_url,
                                    "param": param,
                                    "payload": payload,
                                    "recommendation": "Use parameterized queries / prepared statements",
                                })
                        break
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as executor:
        futures = [executor.submit(_check, p, pl, u) for p, pl, u in jobs]
        for future in as_completed(futures):
            future.result()
            if stop_event.is_set():
                break

    return result_holder


def check_lfi(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for LFI — all param×payload combinations run in parallel,
    returns immediately on first confirmed finding."""
    payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
    ]
    lfi_indicators = ["root:x:0:0", "daemon:", "nobody:", "/bin/bash", "/bin/sh"]
    params = ["file", "page", "include", "path", "template", "view",
              "doc", "document", "load"]

    parsed = urllib.parse.urlparse(base_url)
    jobs: list[tuple[str, str, str]] = []
    for param in params:
        for payload in payloads[:2]:
            qs = urllib.parse.urlencode({param: payload})
            test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
            jobs.append((param, payload, test_url))

    import threading
    stop_event = threading.Event()
    result_holder: list[dict] = []
    lock = threading.Lock()

    def _check(param: str, payload: str, test_url: str) -> None:
        if stop_event.is_set():
            return
        try:
            result = fetch_url(test_url, timeout=timeout)
            if result and not stop_event.is_set():
                body = result.get("body", "")
                for indicator in lfi_indicators:
                    if indicator in body:
                        with lock:
                            if not stop_event.is_set():
                                stop_event.set()
                                result_holder.append({
                                    "type": "Local File Inclusion (LFI)",
                                    "severity": SEVERITY_CRITICAL,
                                    "description": f"LFI detected via ?{param}= — /etc/passwd content found in response",
                                    "url": test_url,
                                    "param": param,
                                    "payload": payload,
                                    "recommendation": "Never pass user input directly to file path functions",
                                })
                        break
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(20, len(jobs))) as executor:
        futures = [executor.submit(_check, p, pl, u) for p, pl, u in jobs]
        for future in as_completed(futures):
            future.result()
            if stop_event.is_set():
                break

    return result_holder


def check_sensitive_files(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for exposed sensitive files — all paths probed in parallel."""
    base_url = base_url.rstrip("/")

    sensitive_paths = [
        ("/.git/HEAD",             "Git repository exposed",                        SEVERITY_HIGH),
        ("/.env",                  "Environment file exposed — may contain secrets", SEVERITY_CRITICAL),
        ("/.env.local",            "Environment file exposed",                       SEVERITY_CRITICAL),
        ("/.env.production",       "Production environment file exposed",             SEVERITY_CRITICAL),
        ("/config.php",            "PHP config file exposed",                         SEVERITY_HIGH),
        ("/wp-config.php",         "WordPress config exposed",                        SEVERITY_CRITICAL),
        ("/phpinfo.php",           "PHP info page exposed",                           SEVERITY_HIGH),
        ("/.htaccess",             "Apache .htaccess exposed",                        SEVERITY_MEDIUM),
        ("/robots.txt",            "robots.txt (informational)",                      SEVERITY_INFO),
        ("/sitemap.xml",           "sitemap.xml (informational)",                     SEVERITY_INFO),
        ("/crossdomain.xml",       "Flash crossdomain policy",                        SEVERITY_LOW),
        ("/clientaccesspolicy.xml","Silverlight client access policy",                SEVERITY_LOW),
        ("/server-status",         "Apache server-status exposed",                    SEVERITY_HIGH),
        ("/server-info",           "Apache server-info exposed",                      SEVERITY_HIGH),
        ("/.DS_Store",             "macOS .DS_Store exposed — leaks directory structure", SEVERITY_LOW),
        ("/backup.sql",            "SQL backup file exposed",                          SEVERITY_CRITICAL),
        ("/dump.sql",              "SQL dump exposed",                                 SEVERITY_CRITICAL),
        ("/database.sql",          "Database backup exposed",                          SEVERITY_CRITICAL),
        ("/.git/config",           "Git config exposed",                               SEVERITY_HIGH),
        ("/package.json",          "package.json exposed",                             SEVERITY_LOW),
        ("/composer.json",         "composer.json exposed",                            SEVERITY_LOW),
        ("/api/swagger.json",      "Swagger/OpenAPI spec exposed",                     SEVERITY_INFO),
        ("/swagger.json",          "Swagger spec exposed",                             SEVERITY_INFO),
        ("/openapi.json",          "OpenAPI spec exposed",                             SEVERITY_INFO),
        ("/actuator",              "Spring Boot actuator exposed",                     SEVERITY_HIGH),
        ("/actuator/env",          "Spring Boot env actuator — may expose secrets",    SEVERITY_CRITICAL),
    ]

    def _check(path: str, description: str, severity: str) -> Optional[dict]:
        url = base_url + path
        try:
            result = fetch_url(url, timeout=timeout, follow_redirects=False)
            if result and result["status"] in (200, 403):
                return {
                    "type": "Sensitive File Exposure",
                    "severity": severity,
                    "description": description,
                    "url": url,
                    "status": result["status"],
                    "recommendation": "Restrict access to sensitive files via web server configuration",
                }
        except Exception:
            pass
        return None

    issues: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(25, len(sensitive_paths))) as executor:
        futures = {
            executor.submit(_check, path, desc, sev): path
            for path, desc, sev in sensitive_paths
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                issues.append(result)

    return issues


def check_http_methods(base_url: str, timeout: int = 5) -> list[dict]:
    """Check for dangerous HTTP methods — all methods probed in parallel."""
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS", "PATCH"]

    def _check(method: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(
                base_url, method=method,
                headers={"User-Agent": "BugBountyTool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (405, 501):
                    if method == "TRACE":
                        return {
                            "type": "Dangerous HTTP Method",
                            "severity": SEVERITY_MEDIUM,
                            "description": f"HTTP {method} method is allowed — TRACE enables XST attacks",
                            "url": base_url,
                            "recommendation": f"Disable HTTP {method} method on the server",
                        }
                    elif method in ("PUT", "DELETE"):
                        return {
                            "type": "Dangerous HTTP Method",
                            "severity": SEVERITY_HIGH,
                            "description": f"HTTP {method} method allowed — may allow unauthorized file manipulation",
                            "url": base_url,
                            "recommendation": f"Disable HTTP {method} unless explicitly needed",
                        }
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501, 403):
                pass
        except Exception:
            pass
        return None

    issues: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(dangerous_methods)) as executor:
        futures = {executor.submit(_check, m): m for m in dangerous_methods}
        for future in as_completed(futures):
            result = future.result()
            if result:
                issues.append(result)

    return issues


if __name__ == "__main__":
    pass
