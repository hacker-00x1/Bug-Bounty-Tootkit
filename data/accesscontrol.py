# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Access Control / IDOR — unauthenticated admin, 403 bypass, IDOR."""

import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/admin/config", "/admin/panel", "/admin/reports", "/admin/logs",
    "/administrator", "/superadmin", "/superuser",
    "/management", "/manage", "/manager",
    "/api/admin", "/api/users", "/api/admin/users", "/api/admin/dashboard",
    "/api/v1/admin", "/api/v2/admin", "/api/internal", "/api/private",
    "/internal", "/private", "/restricted", "/staff", "/support/admin",
    "/dashboard", "/console", "/control", "/controlpanel",
    "/system", "/sys", "/root", "/operator",
    "/actuator", "/actuator/env", "/actuator/health/detail",
    "/actuator/mappings", "/actuator/beans", "/actuator/trace",
    "/actuator/heapdump", "/actuator/logfile",
    "/metrics", "/prometheus", "/grafana",
    "/wp-admin", "/wp-admin/users.php", "/wp-admin/options.php",
    "/phpmyadmin", "/adminer.php", "/pma",
    "/manager/html", "/manager/status",
    "/.env", "/.git", "/config", "/settings",
    "/api/v1/users", "/api/v1/accounts", "/api/v2/users",
    "/api/accounts", "/api/profiles",
    "/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/goroutine",
]

SENSITIVE_WORDS = [
    "user", "email", "dashboard", "manage", "setting", "admin", "account",
    "role", "password", "token", "secret", "config", "panel", "control",
    "system", "log", "report", "statistics", "stats",
]

BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
]

PATH_BYPASSES = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}%20",
    "{path}%09",
    "{path}?",
    "/{path_tail}",
    "{path_head}/..;/{path_tail}",
    "{path}/..",
    "{path}%2e",
]

IDOR_PARAMS = ["id", "user_id", "account_id", "uid", "userId", "customerId",
               "orderId", "fileId", "docId", "profileId", "memberId", "pid"]

CVSS = {"CRITICAL": "9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "HIGH":     "8.1 (High)     — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}


def _check_admin_access(base_url: str, timeout: int) -> list[dict]:
    findings = []
    def _probe(path):
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if not resp:
            return None
        if resp.get("status") == 200:
            body = (resp.get("body") or "").lower()
            if any(w in body for w in SENSITIVE_WORDS) and len(body) > 200:
                return {
                    "type": "Access Control — Unauthenticated Admin Access",
                    "severity": "CRITICAL",
                    "url": url,
                    "cvss": CVSS["CRITICAL"],
                    "description": f"Admin/privileged endpoint accessible without authentication: {path}",
                    "steps_to_reproduce": f"1. curl -s '{url}'\n2. Observe admin interface content without credentials.",
                    "impact": "Attacker gains full administrative access — user management, config changes, data access.",
                    "recommendation": "Enforce authentication middleware on ALL admin routes. Implement IP allowlisting for admin panels.",
                }
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(_probe, ADMIN_PATHS):
            if result:
                findings.append(result)
    return findings


def _check_403_bypass(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in ADMIN_PATHS[:15]:
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if not resp or resp.get("status") != 403:
            continue
        for header_dict in BYPASS_HEADERS:
            headers = {k: v.replace("{path}", path) for k, v in header_dict.items()}
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "BugBountyTool/1.0")
                for k, v in headers.items():
                    req.add_header(k, v)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = (r.read(500) or b"").decode("utf-8", errors="replace").lower()
                    if r.status == 200 and any(w in body for w in SENSITIVE_WORDS):
                        hname, hval = list(headers.items())[0]
                        findings.append({
                            "type": "Access Control — 403 Bypass via Header",
                            "severity": "HIGH",
                            "url": url,
                            "bypass_header": f"{hname}: {hval}",
                            "cvss": CVSS["HIGH"],
                            "description": f"403 on {path} bypassed with HTTP header: {hname}: {hval}",
                            "steps_to_reproduce": (
                                f"1. curl -s '{url}' → 403\n"
                                f"2. curl -s '{url}' -H '{hname}: {hval}' → 200 with admin content"
                            ),
                            "impact": "Attacker bypasses IP/role-based access control to restricted admin resources.",
                            "recommendation": "Never trust X-Forwarded-For or X-Original-URL for authorization. Use server-side session/role checks.",
                        })
                        break
            except Exception:
                pass
    return findings


def _check_idor(base_url: str, timeout: int) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)

    for param in IDOR_PARAMS:
        for seed in ["1", "2", "100"]:
            tqs = {param: [seed]}
            u1 = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(tqs, doseq=True)))
            tqs2 = {param: [str(int(seed) + 1)]}
            u2 = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(tqs2, doseq=True)))
            r1 = fetch_url(u1, timeout=timeout)
            r2 = fetch_url(u2, timeout=timeout)
            if r1 and r2:
                b1 = r1.get("body") or ""
                b2 = r2.get("body") or ""
                if (r1.get("status") == 200 and r2.get("status") == 200
                        and len(b1) > 100 and b1 != b2
                        and any(w in b1.lower() for w in ["email", "name", "user", "account", "id", "profile"])):
                    findings.append({
                        "type": "Access Control — Insecure Direct Object Reference (IDOR)",
                        "severity": "HIGH",
                        "url": u1,
                        "param": param,
                        "cvss": CVSS["HIGH"],
                        "description": f"IDOR via param '{param}': sequential IDs return different user data — no ownership check.",
                        "steps_to_reproduce": (
                            f"1. Authenticated request: curl '{u1}' → your data\n"
                            f"2. Increment: curl '{u2}' → another user's data\n"
                            f"3. Enumerate all IDs to harvest user database."
                        ),
                        "impact": "Access to other users' private data. Full account enumeration possible.",
                        "recommendation": "Use UUIDs instead of sequential IDs. Enforce server-side ownership validation on every request.",
                    })
                    return findings
    return findings


def _check_method_override(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in ["/admin", "/api/users/1", "/api/admin"]:
        url = base_url.rstrip("/") + path
        for override in ["_method=DELETE", "_method=PUT"]:
            try:
                req = urllib.request.Request(url, data=override.encode(), method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                req.add_header("X-HTTP-Method-Override", override.split("=")[1])
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    if r.status in (200, 204):
                        findings.append({
                            "type": "Access Control — HTTP Method Override",
                            "severity": "MEDIUM",
                            "url": url,
                            "description": f"Server accepts X-HTTP-Method-Override to bypass method restrictions at {path}",
                            "steps_to_reproduce": f"1. POST {url} with header X-HTTP-Method-Override: DELETE\n2. Observe 200/204 response.",
                            "impact": "May allow DELETE/PUT operations on restricted resources.",
                            "recommendation": "Validate HTTP methods at router level. Do not honor method override headers on sensitive endpoints.",
                        })
                        break
            except Exception:
                pass
    return findings


def run(base_url: str, domain: str = "", timeout: int = 4, threads: int = 15, **kwargs) -> dict:
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(_check_admin_access, base_url, timeout)
        f2 = ex.submit(_check_403_bypass,   base_url, timeout)
        f3 = ex.submit(_check_idor,         base_url, timeout)
        f4 = ex.submit(_check_method_override, base_url, timeout)
        for f in [f1, f2, f3, f4]:
            findings.extend(f.result())
    return {
        "findings": findings,
        "summary": {
            "admin_paths_checked": len(ADMIN_PATHS),
            "bypass_headers_tried": len(BYPASS_HEADERS),
            "total_findings": len(findings),
            "checks": ["unauthenticated-access", "403-bypass", "idor", "method-override"],
        },
    }


if __name__ == "__main__":
    pass
