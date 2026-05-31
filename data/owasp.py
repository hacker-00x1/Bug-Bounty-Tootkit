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

"""
OWASP Top 10 (2021) — Dedicated scanner module.

Covers checks not handled by other modules:
  A01 – Broken Access Control
  A02 – Cryptographic Failures        (TLS/HTTPS checks)
  A05 – Security Misconfiguration     (default pages, verbose errors)
  A06 – Vulnerable & Outdated Components (version disclosure)
  A07 – Identification & Authentication Failures
  A08 – Software & Data Integrity Failures (missing SRI, CSP)
  A09 – Security Logging & Monitoring Failures (error info disclosure)
  A10 – Server-Side Request Forgery (SSRF)

Checks covered by other modules (cross-referenced, not duplicated):
  A03 – Injection         → vulns.py  (SQLi, LFI) + xss_gen.py (XSS)
  A04 – Insecure Design   → crawler.py (sensitive paths) + vulns.py
"""

import re
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from data.webfuzz import fetch_url

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# A01 — Broken Access Control
# ─────────────────────────────────────────────────────────────────────────────

_ADMIN_PATHS = [
    ("/admin", "Admin panel"),
    ("/admin/", "Admin panel"),
    ("/administrator", "Administrator panel"),
    ("/wp-admin", "WordPress admin"),
    ("/wp-admin/", "WordPress admin"),
    ("/dashboard", "Dashboard"),
    ("/console", "Management console"),
    ("/manager/html", "Tomcat Manager"),
    ("/phpmyadmin", "phpMyAdmin"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/cpanel", "cPanel"),
    ("/plesk", "Plesk"),
    ("/secure", "Secure area"),
    ("/private", "Private area"),
    ("/internal", "Internal area"),
    ("/backend", "Backend"),
    ("/staff", "Staff area"),
    ("/management", "Management"),
    ("/controlpanel", "Control panel"),
    ("/config", "Config panel"),
    ("/api/admin", "Admin API"),
    ("/api/v1/admin", "Admin API v1"),
    ("/api/v2/admin", "Admin API v2"),
    ("/api/users", "Users API — may expose PII"),
    ("/api/user", "User API — may expose PII"),
    ("/api/accounts", "Accounts API"),
    ("/.git/", "Git repository exposed"),
    ("/.svn/", "SVN repository exposed"),
    ("/debug", "Debug endpoint"),
    ("/test", "Test endpoint"),
    ("/staging", "Staging endpoint"),
]

_IDOR_PARAMS = ["id", "user_id", "account", "uid", "pid", "doc_id", "record", "order_id",
                "invoice", "file_id", "customer_id", "profile_id", "user", "member"]


def check_broken_access_control(base_url: str, timeout: int = 5) -> list[dict]:
    """
    A01: Check for exposed admin/private paths and potential IDOR surfaces.
    """
    findings = []
    base = base_url.rstrip("/")

    def probe(path: str, label: str) -> Optional[dict]:
        url = base + path
        try:
            result = fetch_url(url, timeout=timeout, follow_redirects=False)
            if not result:
                return None
            status = result["status"]
            if status in (200, 201, 204):
                return {
                    "type": "A01 — Broken Access Control",
                    "owasp": "A01:2021",
                    "severity": SEVERITY_HIGH,
                    "description": f"Accessible without authentication: {label} ({path})",
                    "url": url,
                    "status": status,
                    "recommendation": "Enforce authentication and role-based access control on all sensitive paths.",
                }
            if status == 403:
                return {
                    "type": "A01 — Broken Access Control",
                    "owasp": "A01:2021",
                    "severity": SEVERITY_MEDIUM,
                    "description": f"Forbidden but path exists — may be bypassable: {label} ({path})",
                    "url": url,
                    "status": status,
                    "recommendation": "Verify that 403 cannot be bypassed via HTTP method override or header manipulation.",
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(probe, p, lbl): (p, lbl) for p, lbl in _ADMIN_PATHS}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                findings.append(r)

    # IDOR surface: check if numeric ID param exists on homepage query string
    parsed = urllib.parse.urlparse(base_url)
    existing_params = list(urllib.parse.parse_qs(parsed.query).keys())
    idor_params = [p for p in existing_params if p.lower() in _IDOR_PARAMS]
    for param in idor_params:
        findings.append({
            "type": "A01 — Potential IDOR Surface",
            "owasp": "A01:2021",
            "severity": SEVERITY_MEDIUM,
            "description": f"Parameter '?{param}=' found in URL — test for Insecure Direct Object Reference (IDOR).",
            "url": base_url,
            "recommendation": "Validate object ownership server-side. Never rely on client-supplied IDs alone.",
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A02 — Cryptographic Failures
# ─────────────────────────────────────────────────────────────────────────────

def check_cryptographic_failures(base_url: str, timeout: int = 8) -> list[dict]:
    """
    A02: Check for HTTP instead of HTTPS, weak TLS, missing HSTS.
    """
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.netloc.split(":")[0]

    if parsed.scheme == "http":
        findings.append({
            "type": "A02 — Cryptographic Failure",
            "owasp": "A02:2021",
            "severity": SEVERITY_HIGH,
            "description": "Site served over HTTP — all data transmitted in plaintext.",
            "url": base_url,
            "recommendation": "Enforce HTTPS site-wide and redirect all HTTP traffic to HTTPS.",
        })
    else:
        # Check TLS certificate and version
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(timeout)
                s.connect((domain, 443))
                cert = s.getpeercert()
                tls_ver = s.version()

                if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "type": "A02 — Weak TLS Version",
                        "owasp": "A02:2021",
                        "severity": SEVERITY_HIGH,
                        "description": f"Server supports deprecated TLS version: {tls_ver}",
                        "url": base_url,
                        "recommendation": "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ only.",
                    })

                # Check cert expiry
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        import datetime
                        try:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.datetime.utcnow()).days
                            if days_left < 0:
                                findings.append({
                                    "type": "A02 — Expired TLS Certificate",
                                    "owasp": "A02:2021",
                                    "severity": SEVERITY_CRITICAL,
                                    "description": f"TLS certificate expired {abs(days_left)} day(s) ago.",
                                    "url": base_url,
                                    "recommendation": "Renew the TLS certificate immediately.",
                                })
                            elif days_left < 30:
                                findings.append({
                                    "type": "A02 — TLS Certificate Expiring Soon",
                                    "owasp": "A02:2021",
                                    "severity": SEVERITY_MEDIUM,
                                    "description": f"TLS certificate expires in {days_left} day(s).",
                                    "url": base_url,
                                    "recommendation": "Renew the TLS certificate before it expires.",
                                })
                        except Exception:
                            pass
        except ssl.SSLCertVerificationError:
            findings.append({
                "type": "A02 — Invalid/Self-Signed TLS Certificate",
                "owasp": "A02:2021",
                "severity": SEVERITY_HIGH,
                "description": "TLS certificate failed verification (self-signed or untrusted CA).",
                "url": base_url,
                "recommendation": "Use a certificate from a trusted CA. Avoid self-signed certs in production.",
            })
        except Exception:
            pass

        # Check HTTP→HTTPS redirect
        http_url = "http://" + parsed.netloc + (parsed.path or "/")
        try:
            result = fetch_url(http_url, timeout=timeout, follow_redirects=False)
            if result and result["status"] not in (301, 302, 307, 308):
                findings.append({
                    "type": "A02 — HTTP Not Redirected to HTTPS",
                    "owasp": "A02:2021",
                    "severity": SEVERITY_MEDIUM,
                    "description": "HTTP version of the site does not redirect to HTTPS.",
                    "url": http_url,
                    "recommendation": "Add a permanent 301 redirect from HTTP to HTTPS.",
                })
        except Exception:
            pass

    # Check HSTS header
    try:
        result = fetch_url(base_url, timeout=timeout, follow_redirects=True)
        if result:
            headers = result.get("headers", {})
            hsts = headers.get("strict-transport-security", "")
            if not hsts:
                findings.append({
                    "type": "A02 — Missing HSTS Header",
                    "owasp": "A02:2021",
                    "severity": SEVERITY_MEDIUM,
                    "description": "Strict-Transport-Security header not set — browsers may allow HTTP fallback.",
                    "url": base_url,
                    "recommendation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                })
            else:
                if "includesubdomains" not in hsts.lower():
                    findings.append({
                        "type": "A02 — HSTS Missing includeSubDomains",
                        "owasp": "A02:2021",
                        "severity": SEVERITY_LOW,
                        "description": "HSTS header present but missing includeSubDomains directive.",
                        "url": base_url,
                        "recommendation": "Add includeSubDomains to the HSTS header.",
                    })
    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A05 — Security Misconfiguration
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_PAGES = [
    ("/index.php", "PHP default page"),
    ("/test.php", "PHP test file"),
    ("/info.php", "PHP info file"),
    ("/phpinfo.php", "PHP info file"),
    ("/default.asp", "ASP default page"),
    ("/elmah.axd", "ELMAH error log (ASP.NET)"),
    ("/trace.axd", "ASP.NET trace viewer"),
    ("/error_log", "Error log exposed"),
    ("/error.log", "Error log exposed"),
    ("/access.log", "Access log exposed"),
    ("/.htpasswd", "Apache htpasswd exposed"),
    ("/web.config", "IIS web.config exposed"),
    ("/WEB-INF/web.xml", "Java web.xml exposed"),
    ("/META-INF/MANIFEST.MF", "Java manifest exposed"),
    ("/.bash_history", "Bash history exposed"),
    ("/.ssh/id_rsa", "SSH private key exposed"),
    ("/id_rsa", "SSH private key exposed"),
    ("/server-info", "Apache server info"),
    ("/server-status", "Apache server status"),
]


def check_security_misconfiguration(base_url: str, timeout: int = 5) -> list[dict]:
    """
    A05: Default pages, verbose error pages, misconfigured headers.
    """
    findings = []
    base = base_url.rstrip("/")

    def probe(path, label):
        url = base + path
        try:
            result = fetch_url(url, timeout=timeout, follow_redirects=False)
            if result and result["status"] == 200:
                return {
                    "type": "A05 — Security Misconfiguration",
                    "owasp": "A05:2021",
                    "severity": SEVERITY_HIGH,
                    "description": f"{label} accessible: {path}",
                    "url": url,
                    "recommendation": "Remove or restrict access to default/debug/config files.",
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(probe, p, l): (p, l) for p, l in _DEFAULT_PAGES}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                findings.append(r)

    # Check for verbose error disclosure
    error_url = base_url.rstrip("/") + "/<INVALID_PATH_9z3q>"
    try:
        result = fetch_url(error_url, timeout=timeout, follow_redirects=False)
        if result:
            body = result.get("body", "").lower()
            error_patterns = [
                ("stack trace", "Stack trace exposed in error page"),
                ("exception in", "Java/Python exception exposed"),
                ("syntax error", "Syntax error message exposed"),
                ("warning:", "PHP warning exposed"),
                ("sql syntax", "SQL syntax error exposed — may indicate SQLi surface"),
                ("uncaught exception", "Uncaught exception disclosed"),
                ("at line ", "Line number disclosed in error"),
                ("traceback (most recent", "Python traceback exposed"),
                ("system.web", "ASP.NET internals exposed"),
            ]
            for pattern, description in error_patterns:
                if pattern in body:
                    findings.append({
                        "type": "A05 — Verbose Error Disclosure",
                        "owasp": "A05:2021",
                        "severity": SEVERITY_MEDIUM,
                        "description": description,
                        "url": error_url,
                        "recommendation": "Configure generic error pages. Never expose stack traces or internal paths in production.",
                    })
                    break
    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A06 — Vulnerable and Outdated Components
# ─────────────────────────────────────────────────────────────────────────────

_VERSION_PATTERNS = [
    (r"Apache/(\d+\.\d+\.\d+)", "Apache", {"2.2": SEVERITY_HIGH, "2.4": SEVERITY_INFO}),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx", {}),
    (r"PHP/(\d+\.\d+\.\d+)", "PHP", {"5.": SEVERITY_CRITICAL, "7.0": SEVERITY_HIGH, "7.1": SEVERITY_HIGH, "7.2": SEVERITY_MEDIUM}),
    (r"OpenSSL/(\d+\.\d+\.\d+\w*)", "OpenSSL", {}),
    (r"Microsoft-IIS/(\d+\.\d+)", "IIS", {"6.": SEVERITY_CRITICAL, "7.": SEVERITY_HIGH}),
    (r"Tomcat/(\d+\.\d+\.\d+)", "Tomcat", {}),
    (r"WordPress/(\d+\.\d+)", "WordPress", {}),
    (r"Drupal (\d+)", "Drupal", {}),
    (r"Joomla! (\d+\.\d+)", "Joomla", {}),
    (r"jQuery v?(\d+\.\d+\.\d+)", "jQuery", {"1.": SEVERITY_HIGH, "2.": SEVERITY_MEDIUM}),
    (r"Bootstrap v?(\d+\.\d+\.\d+)", "Bootstrap", {}),
    (r"X-Powered-By: PHP/(\d+\.\d+)", "PHP (X-Powered-By)", {"5.": SEVERITY_CRITICAL, "7.0": SEVERITY_HIGH}),
    (r"X-AspNet-Version: (\d+\.\d+)", "ASP.NET", {}),
    (r"X-Generator: (.+)", "Generator (CMS)", {}),
]


def check_outdated_components(base_url: str, timeout: int = 8) -> list[dict]:
    """
    A06: Detect server/software version disclosure and flag EOL versions.
    """
    findings = []
    try:
        result = fetch_url(base_url, timeout=timeout, follow_redirects=True)
        if not result:
            return findings

        headers = result.get("headers", {})
        body = result.get("body", "")

        # Combine headers into a searchable string
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_str + "\n" + body

        for pattern, component, version_severity in _VERSION_PATTERNS:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                version = m.group(1)
                severity = SEVERITY_INFO
                for prefix, sev in version_severity.items():
                    if version.startswith(prefix):
                        severity = sev
                        break

                findings.append({
                    "type": "A06 — Component Version Disclosure",
                    "owasp": "A06:2021",
                    "severity": severity,
                    "description": f"{component} version disclosed: {version}",
                    "url": base_url,
                    "recommendation": f"Suppress version information in headers/responses. Keep {component} updated to latest stable.",
                })

        # Check for Server header disclosure
        server = headers.get("server", "")
        if server and server not in ("cloudflare", "nginx", "apache"):
            if re.search(r"\d+\.\d+", server):
                findings.append({
                    "type": "A06 — Server Header Version Disclosure",
                    "owasp": "A06:2021",
                    "severity": SEVERITY_LOW,
                    "description": f"Server header reveals version: {server}",
                    "url": base_url,
                    "recommendation": "Configure the web server to suppress the Server header or remove version info.",
                })

        # X-Powered-By disclosure
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append({
                "type": "A06 — Technology Disclosure via X-Powered-By",
                "owasp": "A06:2021",
                "severity": SEVERITY_LOW,
                "description": f"X-Powered-By header discloses technology: {powered_by}",
                "url": base_url,
                "recommendation": "Remove the X-Powered-By header.",
            })

    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A07 — Identification and Authentication Failures
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", ""),
]

_LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/user/login",
    "/wp-login.php", "/admin/login", "/auth", "/account/login",
    "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth",
]


def check_auth_failures(base_url: str, timeout: int = 6) -> list[dict]:
    """
    A07: Check for weak session handling, missing auth headers, default creds.
    """
    findings = []
    base = base_url.rstrip("/")

    # Locate login page
    login_url = None
    for path in _LOGIN_PATHS:
        try:
            url = base + path
            result = fetch_url(url, timeout=timeout, follow_redirects=True)
            if result and result["status"] == 200:
                body = result.get("body", "").lower()
                if any(kw in body for kw in ["password", "login", "sign in", "username", "email"]):
                    login_url = url
                    break
        except Exception:
            pass

    if login_url:
        # Try default credentials via form POST
        for user, passwd in _DEFAULT_CREDS[:5]:
            try:
                data = urllib.parse.urlencode({"username": user, "password": passwd,
                                               "email": user, "user": user, "pass": passwd}).encode()
                req = urllib.request.Request(login_url, data=data, method="POST",
                                             headers={"Content-Type": "application/x-www-form-urlencoded",
                                                      "User-Agent": "BugBountyTool/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read(5000).decode("utf-8", errors="replace").lower()
                    if any(kw in body for kw in ["dashboard", "logout", "welcome", "profile", "account"]):
                        findings.append({
                            "type": "A07 — Default Credentials Accepted",
                            "owasp": "A07:2021",
                            "severity": SEVERITY_CRITICAL,
                            "description": f"Default credentials accepted: {user}/{passwd}",
                            "url": login_url,
                            "recommendation": "Disable or change all default credentials. Implement account lockout after failed attempts.",
                        })
                        break
            except Exception:
                pass

    # Check for insecure session cookie flags
    try:
        result = fetch_url(base_url, timeout=timeout, follow_redirects=True)
        if result:
            headers = result.get("headers", {})
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                cookies_lower = set_cookie.lower()
                if "httponly" not in cookies_lower:
                    findings.append({
                        "type": "A07 — Session Cookie Missing HttpOnly",
                        "owasp": "A07:2021",
                        "severity": SEVERITY_MEDIUM,
                        "description": "Session cookie set without HttpOnly flag — accessible via JavaScript (XSS risk).",
                        "url": base_url,
                        "recommendation": "Set HttpOnly flag on all session cookies.",
                    })
                if "secure" not in cookies_lower and urllib.parse.urlparse(base_url).scheme == "https":
                    findings.append({
                        "type": "A07 — Session Cookie Missing Secure Flag",
                        "owasp": "A07:2021",
                        "severity": SEVERITY_MEDIUM,
                        "description": "Session cookie set without Secure flag — may be sent over HTTP.",
                        "url": base_url,
                        "recommendation": "Set Secure flag on all session cookies when served over HTTPS.",
                    })
                if "samesite" not in cookies_lower:
                    findings.append({
                        "type": "A07 — Session Cookie Missing SameSite",
                        "owasp": "A07:2021",
                        "severity": SEVERITY_LOW,
                        "description": "Session cookie missing SameSite attribute — may be vulnerable to CSRF.",
                        "url": base_url,
                        "recommendation": "Add SameSite=Strict or SameSite=Lax to session cookies.",
                    })

            # Check for missing auth on API endpoints
            api_url = base + "/api/me"
            api_result = fetch_url(api_url, timeout=timeout, follow_redirects=False)
            if api_result and api_result["status"] == 200:
                findings.append({
                    "type": "A07 — Unauthenticated API Endpoint",
                    "owasp": "A07:2021",
                    "severity": SEVERITY_HIGH,
                    "description": "/api/me accessible without authentication — may expose user data.",
                    "url": api_url,
                    "recommendation": "Require authentication on all API endpoints that return user data.",
                })

    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A08 — Software and Data Integrity Failures
# ─────────────────────────────────────────────────────────────────────────────

def check_integrity_failures(base_url: str, timeout: int = 8) -> list[dict]:
    """
    A08: Check for missing Subresource Integrity (SRI) on external scripts/styles,
    missing Content-Security-Policy.
    """
    findings = []
    try:
        result = fetch_url(base_url, timeout=timeout, follow_redirects=True)
        if not result:
            return findings

        headers = result.get("headers", {})
        body = result.get("body", "")

        # CSP check
        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append({
                "type": "A08 — Missing Content-Security-Policy",
                "owasp": "A08:2021",
                "severity": SEVERITY_MEDIUM,
                "description": "No Content-Security-Policy header — browser will execute any injected scripts.",
                "url": base_url,
                "recommendation": "Implement a Content-Security-Policy header with a strict script-src directive.",
            })
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            directive = "unsafe-inline" if "unsafe-inline" in csp else "unsafe-eval"
            findings.append({
                "type": "A08 — Weak Content-Security-Policy",
                "owasp": "A08:2021",
                "severity": SEVERITY_MEDIUM,
                "description": f"CSP contains '{directive}' — significantly weakens XSS protection.",
                "url": base_url,
                "recommendation": f"Remove '{directive}' from Content-Security-Policy. Use nonces or hashes instead.",
            })

        # SRI check for external scripts
        external_scripts = re.findall(
            r'<script[^>]+src=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>', body, re.IGNORECASE
        )
        sri_scripts = re.findall(r'<script[^>]+integrity=["\']', body, re.IGNORECASE)

        parsed_base = urllib.parse.urlparse(base_url)
        external_no_sri = []
        for src in external_scripts:
            parsed_src = urllib.parse.urlparse(src)
            if parsed_src.netloc != parsed_base.netloc:
                # Check if this script has integrity attribute
                script_pattern = re.search(
                    re.escape(src) + r'[^>]*integrity', body, re.IGNORECASE
                )
                if not script_pattern:
                    external_no_sri.append(src)

        if external_no_sri:
            findings.append({
                "type": "A08 — External Scripts Without SRI",
                "owasp": "A08:2021",
                "severity": SEVERITY_MEDIUM,
                "description": f"{len(external_no_sri)} external script(s) loaded without Subresource Integrity (SRI): "
                               + ", ".join(external_no_sri[:3]),
                "url": base_url,
                "recommendation": "Add integrity and crossorigin attributes to all external scripts and stylesheets.",
            })

    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A09 — Security Logging and Monitoring Failures
# ─────────────────────────────────────────────────────────────────────────────

def check_logging_failures(base_url: str, timeout: int = 6) -> list[dict]:
    """
    A09: Detect log/monitoring file exposure and verbose error info disclosure.
    """
    findings = []
    base = base_url.rstrip("/")

    log_paths = [
        ("/error_log", "Error log"),
        ("/error.log", "Error log"),
        ("/access.log", "Access log"),
        ("/debug.log", "Debug log"),
        ("/application.log", "Application log"),
        ("/logs/error.log", "Error log (logs/)"),
        ("/logs/access.log", "Access log (logs/)"),
        ("/logs/debug.log", "Debug log (logs/)"),
        ("/var/log/nginx/access.log", "Nginx access log"),
        ("/storage/logs/laravel.log", "Laravel log"),
        ("/app/logs/application.log", "App log"),
        ("/wp-content/debug.log", "WordPress debug log"),
    ]

    def probe(path, label):
        url = base + path
        try:
            result = fetch_url(url, timeout=timeout, follow_redirects=False)
            if result and result["status"] == 200:
                body = result.get("body", "")
                if any(kw in body.lower() for kw in ["error", "warning", "exception", "fatal", "notice", "debug"]):
                    return {
                        "type": "A09 — Log File Exposed",
                        "owasp": "A09:2021",
                        "severity": SEVERITY_HIGH,
                        "description": f"{label} publicly accessible — may contain IP addresses, paths, and internal errors.",
                        "url": url,
                        "recommendation": "Store log files outside the web root and restrict access via web server config.",
                    }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(probe, p, l): (p, l) for p, l in log_paths}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                findings.append(r)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# A10 — Server-Side Request Forgery (SSRF)
# ─────────────────────────────────────────────────────────────────────────────

_SSRF_PARAMS = [
    "url", "redirect", "link", "src", "source", "dest", "destination",
    "target", "host", "proxy", "callback", "return", "next", "path",
    "fetch", "load", "file", "resource", "uri", "endpoint", "image",
    "img", "feed", "webhook", "api", "service", "backend", "forward",
]

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",      # AWS IMDS
    "http://169.254.169.254/",                         # AWS IMDS short
    "http://metadata.google.internal/",               # GCP metadata
    "http://100.100.100.200/latest/meta-data/",       # Alibaba IMDS
    "http://192.168.0.1/",                            # Internal network
    "http://10.0.0.1/",                               # RFC1918
    "http://127.0.0.1/",                              # Localhost
    "http://localhost/",                              # Localhost
    "http://[::1]/",                                  # IPv6 localhost
    "http://0.0.0.0/",                               # All interfaces
]

_SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-hostname",       # AWS
    "project-id", "google", "service-account",       # GCP
    "connection refused", "no route to host",        # Network error (SSRF triggered)
    "root:x:", "www-data",                           # /etc/passwd
]


def check_ssrf(base_url: str, timeout: int = 6) -> list[dict]:
    """
    A10: Probe URL-like parameters for SSRF to cloud metadata and internal hosts.
    """
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    base = base_url.rstrip("/")

    # Find URL-like params in the existing query string
    existing_params = list(urllib.parse.parse_qs(parsed.query).keys())
    ssrf_params = [p for p in existing_params if p.lower() in _SSRF_PARAMS]

    # Also probe common SSRF params even if not in URL
    test_params = list(set(ssrf_params + _SSRF_PARAMS[:8]))

    for param in test_params[:10]:
        for payload in _SSRF_PAYLOADS[:4]:
            try:
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                new_qs = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

                result = fetch_url(test_url, timeout=timeout, follow_redirects=False)
                if not result:
                    continue

                body = result.get("body", "").lower()
                status = result.get("status", 0)

                for indicator in _SSRF_INDICATORS:
                    if indicator.lower() in body:
                        findings.append({
                            "type": "A10 — Server-Side Request Forgery (SSRF)",
                            "owasp": "A10:2021",
                            "severity": SEVERITY_CRITICAL,
                            "description": f"SSRF confirmed via '?{param}={payload}' — response contains '{indicator}'.",
                            "url": test_url,
                            "recommendation": "Validate and whitelist allowed URLs. Block requests to internal IPs and cloud metadata endpoints.",
                        })
                        return findings

                # Timing-based SSRF heuristic: internal IP takes much longer than external
                if status in (200, 500) and "169.254.169.254" in payload:
                    findings.append({
                        "type": "A10 — Potential SSRF (Internal IP Reachable)",
                        "owasp": "A10:2021",
                        "severity": SEVERITY_HIGH,
                        "description": f"Parameter '?{param}=' returned a response when set to cloud metadata URL — possible SSRF.",
                        "url": test_url,
                        "recommendation": "Validate and whitelist allowed external URLs. Block access to RFC1918 and link-local ranges.",
                    })
                    break

            except Exception:
                pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Combined runner
# ─────────────────────────────────────────────────────────────────────────────

def run_owasp_top10(base_url: str, timeout: int = 6) -> dict:
    """
    Run all OWASP Top 10 checks and return a structured results dict.
    """
    results = {
        "a01_broken_access_control": [],
        "a02_cryptographic_failures": [],
        "a05_security_misconfiguration": [],
        "a06_outdated_components": [],
        "a07_auth_failures": [],
        "a08_integrity_failures": [],
        "a09_logging_failures": [],
        "a10_ssrf": [],
    }

    checkers = [
        ("a01_broken_access_control",  check_broken_access_control),
        ("a02_cryptographic_failures",  check_cryptographic_failures),
        ("a05_security_misconfiguration", check_security_misconfiguration),
        ("a06_outdated_components",     check_outdated_components),
        ("a07_auth_failures",           check_auth_failures),
        ("a08_integrity_failures",      check_integrity_failures),
        ("a09_logging_failures",        check_logging_failures),
        ("a10_ssrf",                    check_ssrf),
    ]

    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(fn, base_url, timeout): key for key, fn in checkers}
        for fut in as_completed(futs):
            key = futs[fut]
            try:
                results[key] = fut.result()
            except Exception:
                results[key] = []

    all_findings = []
    for v in results.values():
        all_findings.extend(v)

    counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    results["summary"] = {
        "total": len(all_findings),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "info": counts.get("INFO", 0),
        "all_findings": all_findings,
    }

    return results


def as_findings(owasp_results: dict) -> list[dict]:
    return owasp_results.get("summary", {}).get("all_findings", [])


if __name__ == "__main__":
    pass
