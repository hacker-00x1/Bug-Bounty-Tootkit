# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Authentication Testing — default creds, cookie flags, JWT, enumeration."""

import urllib.parse
import urllib.request
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),("admin","admin123"),
    ("admin",""),("admin","letmein"),("admin","welcome"),("admin","1234"),
    ("admin","qwerty"),("admin","changeme"),("admin","Password1"),("admin","Admin@123"),
    ("root","root"),("root","toor"),("root","password"),("root",""),
    ("administrator","administrator"),("administrator","password"),
    ("test","test"),("test","password"),("guest","guest"),("guest",""),
    ("user","user"),("user","password"),("demo","demo"),("info","info"),
    ("operator","operator"),("support","support"),("service","service"),
    ("manager","manager"),("superuser","superuser"),("sa",""),("sa","sa"),
]

LOGIN_PATHS = [
    "/login","/signin","/admin","/admin/login","/administrator",
    "/wp-login.php","/wp-admin","/user/login","/account/login",
    "/auth/login","/panel","/cpanel","/console","/dashboard",
    "/login.php","/login.aspx","/login.jsp","/admin.php",
    "/manager/html","/phpmyadmin","/adminer.php","/api/login",
    "/api/auth","/api/signin","/api/v1/login","/auth",
]

WEAK_JWT_SECRETS = [
    "secret","password","123456","jwt_secret","your-secret-key",
    "changeme","supersecret","mysecret","jwttoken","token",
]

COOKIE_FLAGS = ["httponly","secure","samesite"]
SENSITIVE_COOKIE_NAMES = ["session","auth","token","sid","jwt","user","login","remember"]

CVSS_CRIT = "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "7.5 (High)     — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_MED  = "5.4 (Medium)   — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"


def _find_login_pages(base_url: str, timeout: int) -> list[str]:
    pages = []
    def _probe(path):
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if resp and resp.get("status") in (200, 302):
            body = (resp.get("body") or "").lower()
            if "<form" in body and ("password" in body or "passwd" in body):
                return url
        return None
    with ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(_probe, LOGIN_PATHS):
            if r:
                pages.append(r)
    return pages


def _check_cookie_flags(base_url: str, timeout: int) -> list[dict]:
    findings = []
    resp = fetch_url(base_url, timeout=timeout)
    if not resp:
        return findings
    headers = resp.get("headers") or {}
    raw = headers.get("set-cookie", "") or ""
    cookies = raw if isinstance(raw, list) else [raw]
    for cookie in cookies:
        if not cookie:
            continue
        cl = cookie.lower()
        name = cookie.split("=")[0].strip().lower()
        is_sensitive = any(s in name for s in SENSITIVE_COOKIE_NAMES)
        if not is_sensitive:
            continue
        for flag, sev, desc, rec in [
            ("httponly", "HIGH",   "Missing HttpOnly flag — XSS can steal cookie",
             "Add HttpOnly flag to prevent JavaScript access."),
            ("secure",   "HIGH",   "Missing Secure flag — cookie sent over HTTP",
             "Add Secure flag to enforce HTTPS-only transmission."),
            ("samesite", "MEDIUM", "Missing SameSite flag — CSRF risk",
             "Add SameSite=Strict or Lax to prevent CSRF."),
        ]:
            if flag not in cl:
                findings.append({
                    "type": f"Auth — Cookie Missing {flag.title()} Flag",
                    "severity": sev,
                    "url": base_url,
                    "cookie": cookie[:100],
                    "cvss": CVSS_HIGH if sev == "HIGH" else CVSS_MED,
                    "description": f"Sensitive cookie '{name}' is {desc}",
                    "steps_to_reproduce": (
                        f"1. curl -I '{base_url}' | grep -i set-cookie\n"
                        f"2. Observe '{name}' cookie lacks {flag.title()} attribute."
                    ),
                    "impact": "Session hijacking via XSS, network sniffing, or CSRF attacks.",
                    "recommendation": rec,
                })
    return findings


def _check_default_creds(login_url: str, timeout: int) -> list[dict]:
    findings = []
    for user, pwd in DEFAULT_CREDS:
        for payload_type in ["json", "form"]:
            try:
                if payload_type == "json":
                    import json
                    data = json.dumps({"username": user, "email": user, "password": pwd}).encode()
                    ctype = "application/json"
                else:
                    data = urllib.parse.urlencode({"username": user,"email":user,"password":pwd}).encode()
                    ctype = "application/x-www-form-urlencoded"
                req = urllib.request.Request(login_url, data=data, method="POST")
                req.add_header("Content-Type", ctype)
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(3000).decode("utf-8", errors="replace").lower()
                    status = r.status
                if status in (200, 302) and any(w in body for w in
                        ["dashboard","welcome","logout","profile","admin panel","success","authenticated"]):
                    findings.append({
                        "type": "Auth — Default Credentials Accepted",
                        "severity": "CRITICAL",
                        "url": login_url,
                        "credential": f"{user}:{pwd}",
                        "cvss": CVSS_CRIT,
                        "description": f"Default credentials accepted: {user}:{pwd} → authenticated successfully.",
                        "steps_to_reproduce": (
                            f"1. POST {login_url} with username={user}&password={pwd}\n"
                            "2. Observe 200/302 with authenticated dashboard content."
                        ),
                        "impact": "Immediate full account takeover. If admin credentials, complete application compromise.",
                        "recommendation": "Enforce credential change on first login. Ban common/default passwords. Implement lockout after 5 failures.",
                    })
                    return findings
                break
            except Exception:
                continue
    return findings


def _check_user_enumeration(login_url: str, timeout: int) -> list[dict]:
    findings = []
    responses = {}
    for user, label in [("admin@test-nonexistent-xyz.com", "valid_like"),
                         ("nonexistent_xyz_user@noreply.invalid", "invalid")]:
        data = urllib.parse.urlencode({"username": user, "email": user, "password": "WrongPass!123"}).encode()
        try:
            req = urllib.request.Request(login_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "BugBountyTool/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                responses[label] = r.read(1000).decode("utf-8", errors="replace").lower()
        except Exception:
            pass
    if len(responses) == 2:
        r1, r2 = responses["valid_like"], responses["invalid"]
        # Different error messages → enumeration possible
        if r1 != r2:
            wrong_pw_hints = ["invalid password","wrong password","incorrect password","bad password"]
            if any(h in r1 for h in wrong_pw_hints) and not any(h in r2 for h in wrong_pw_hints):
                findings.append({
                    "type": "Auth — Username Enumeration",
                    "severity": "MEDIUM",
                    "url": login_url,
                    "cvss": CVSS_MED,
                    "description": "Login endpoint returns different error messages for valid vs invalid usernames.",
                    "steps_to_reproduce": (
                        "1. POST with existing username + wrong password → 'Invalid password'\n"
                        "2. POST with non-existent username + wrong password → 'User not found'\n"
                        "3. Enumerate valid users by observing error message differences."
                    ),
                    "impact": "Attacker enumerates valid usernames to target with brute-force or phishing.",
                    "recommendation": "Return a generic message: 'Invalid username or password' regardless of which is wrong.",
                })
    return findings


def _check_jwt_in_response(base_url: str, timeout: int) -> list[dict]:
    findings = []
    resp = fetch_url(base_url, timeout=timeout)
    if not resp:
        return findings
    body = resp.get("body") or ""
    pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    tokens = re.findall(pattern, body)
    for token in tokens[:2]:
        header_b64 = token.split(".")[0]
        try:
            import base64
            pad = header_b64 + "=="
            header = base64.b64decode(pad.encode()).decode("utf-8", errors="replace")
            alg = re.search(r'"alg"\s*:\s*"([^"]+)"', header)
            alg_val = alg.group(1) if alg else "unknown"
        except Exception:
            alg_val = "unknown"
        findings.append({
            "type": "Auth — JWT Token Exposed in Response",
            "severity": "HIGH",
            "url": base_url,
            "token_preview": token[:60] + "...",
            "algorithm": alg_val,
            "cvss": CVSS_HIGH,
            "description": f"JWT token ({alg_val} algorithm) found in response body — should be in HttpOnly cookie.",
            "steps_to_reproduce": f"1. curl -s '{base_url}' | grep -oP 'eyJ[A-Za-z0-9_.-]+'\n2. Decode at jwt.io.",
            "impact": "Token exposed to XSS. If weak secret, token can be forged offline.",
            "recommendation": "Store JWTs in HttpOnly cookies. Use RS256. Validate exp/iat/aud claims.",
        })
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 10, **kwargs) -> dict:
    findings: list[dict] = []
    login_pages = _find_login_pages(base_url, timeout)
    findings.extend(_check_cookie_flags(base_url, timeout))
    findings.extend(_check_jwt_in_response(base_url, timeout))
    with ThreadPoolExecutor(max_workers=min(threads, max(1, len(login_pages) * 2))) as ex:
        cred_futures = [ex.submit(_check_default_creds, p, timeout) for p in login_pages[:3]]
        enum_futures = [ex.submit(_check_user_enumeration, p, timeout) for p in login_pages[:3]]
        for f in as_completed(cred_futures + enum_futures):
            findings.extend(f.result())
    return {
        "findings": findings,
        "login_pages_found": login_pages,
        "summary": {
            "login_pages": len(login_pages),
            "total_findings": len(findings),
            "checks": ["cookie-flags", "jwt-exposure", "default-creds", "user-enumeration"],
        },
    }


if __name__ == "__main__":
    pass
