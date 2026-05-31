"""validator.py — Re-validates scanner findings before report generation.

For every finding from every scanner module, sends a targeted HTTP request
and checks the response for concrete proof the vulnerability is real.
Attaches evidence (exact HTTP request + response snippet) to each finding,
then marks it:

  confidence = "confirmed"   — reproduced with hard evidence
  confidence = "likely"      — strong indicator; requires OOB / manual check
  confidence = "rejected"    — could not reproduce; finding is a false positive

Only "confirmed" and "likely" findings appear in reports.
"rejected" findings are stored under results["validation"]["rejected"].
"""

from __future__ import annotations

import re
import time
import threading
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DEFAULT_TIMEOUT = 6
_UA = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"

_SQL_ERROR_PATTERNS = re.compile(
    r"(You have an error in your SQL syntax"
    r"|ORA-\d{4,}"
    r"|SQLSTATE\["
    r"|quoted string not properly terminated"
    r"|Unclosed quotation mark"
    r"|microsoft ole db provider for sql"
    r"|mysql_fetch_array\(\)"
    r"|pg_query\(\)"
    r"|syntax error.{0,60}near"
    r"|unexpected token.{0,60}near"
    r"|warning: mysql"
    r"|supplied argument is not a valid mysql)"
    , re.I
)

_LFI_PATTERNS = re.compile(
    r"(root:x:0:0|root:!:0:0|bin:x:\d+:\d+|/bin/bash|/bin/sh"
    r"|\[boot loader\]|\[operating systems\]"
    r"|for 16-bit app support)"
    , re.I
)

_TAKEOVER_SIGNATURES: dict[str, re.Pattern] = {
    "github":      re.compile(r"there isn.t a github pages site here", re.I),
    "heroku":      re.compile(r"no such app|heroku.*not found", re.I),
    "shopify":     re.compile(r"sorry, this shop is currently unavailable", re.I),
    "aws_s3":      re.compile(r"<Code>NoSuchBucket</Code>", re.I),
    "fastly":      re.compile(r"fastly error: unknown domain", re.I),
    "pantheon":    re.compile(r"the gods are wise", re.I),
    "zendesk":     re.compile(r"help center closed", re.I),
    "ghost":       re.compile(r"the thing you were looking for is no longer here", re.I),
    "surge":       re.compile(r"project not found", re.I),
    "teamwork":    re.compile(r"oops - we didn.t find your site", re.I),
    "netlify":     re.compile(r"not found - request id", re.I),
    "vercel":      re.compile(r"the deployment you.re looking for doesn.t exist", re.I),
}

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
]

_SENSITIVE_FILE_PATTERNS = re.compile(
    r"(\[database\]|\[mysql\]|password\s*=\s*\S"
    r"|DB_PASSWORD|secret_key|api_key|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"
    r"|aws_access_key_id|mongodb\+srv://)"
    , re.I
)

# Thread-local storage for per-thread sessions
_thread_local = threading.local()


def _get_session(ignore_ssl: bool) -> requests.Session:
    """Return a per-thread requests.Session (created once per thread)."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.verify = not ignore_ssl
        s.headers["User-Agent"] = _UA
        _thread_local.session = s
        _thread_local.ignore_ssl = ignore_ssl
    elif _thread_local.ignore_ssl != ignore_ssl:
        _thread_local.session.verify = not ignore_ssl
        _thread_local.ignore_ssl = ignore_ssl
    return _thread_local.session


def _format_request(prepared: requests.PreparedRequest) -> str:
    parsed = urlparse(prepared.url or "")
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines  = [f"{prepared.method} {path} HTTP/1.1"]
    host   = parsed.netloc or prepared.headers.get("Host", "")
    lines.append(f"Host: {host}")
    for k, v in prepared.headers.items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    if prepared.body:
        body = prepared.body if isinstance(prepared.body, str) else prepared.body.decode("utf-8", "replace")
        lines += ["", body[:600]]
    return "\n".join(lines)


def _format_response(resp: requests.Response, highlight_pattern: Optional[str] = None,
                     snippet_bytes: int = 800) -> str:
    lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    try:
        body = resp.text
    except Exception:
        body = ""
    if highlight_pattern and highlight_pattern in body:
        idx   = body.find(highlight_pattern)
        start = max(0, idx - 120)
        end   = min(len(body), idx + len(highlight_pattern) + 120)
        snippet = body[start:end].strip()
        lines.append(f"[...] {snippet} [...]")
    else:
        lines.append(body[:snippet_bytes].strip())
    return "\n".join(lines)


def _inject_param(url: str, param: str, value: str) -> str:
    parsed   = urlparse(url)
    qs       = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _evidence(request_str: str, response_str: str, note: str, status: int, ms: float) -> dict:
    return {
        "request":          request_str,
        "response":         response_str,
        "validation_note":  note,
        "http_status":      status,
        "response_time_ms": round(ms, 1),
    }


def _reject(note: str) -> dict:
    return {"confidence": "rejected", "evidence": {"validation_note": note}}


def _likely(note: str, request_str: str = "", response_str: str = "") -> dict:
    return {
        "confidence": "likely",
        "evidence": {
            "request":         request_str,
            "response":        response_str,
            "validation_note": note,
        },
    }


def _confirm(note: str, request_str: str, response_str: str, status: int, ms: float) -> dict:
    return {
        "confidence": "confirmed",
        "evidence":   _evidence(request_str, response_str, note, status, ms),
    }


def _validate_missing_header(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session  = _get_session(ignore_ssl)
    url      = finding.get("url", "")
    hdr_name = finding.get("header", "")
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    try:
        t0   = time.time()
        req  = requests.Request("GET", url)
        prep = session.prepare_request(req)
        resp = session.send(prep, timeout=timeout, allow_redirects=True)
        ms   = (time.time() - t0) * 1000
        req_s = _format_request(prep)
        hdr_dump = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        resp_s = f"HTTP/1.1 {resp.status_code} {resp.reason}\n{hdr_dump}"
        if hdr_name and hdr_name.lower() in {k.lower() for k in resp.headers}:
            return _reject(f"Header `{hdr_name}` IS present — false positive.")
        note = (
            f"Confirmed: `{hdr_name}` is absent from the response headers."
            if hdr_name else "Security header absent from response."
        )
        return _confirm(note, req_s, resp_s, resp.status_code, ms)
    except Exception as exc:
        return _likely(f"Could not reach `{url}`: {exc}")


def _validate_cors(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url    = finding.get("url", "")
    origin = finding.get("origin_sent", "https://evil.com")
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    try:
        t0   = time.time()
        req  = requests.Request("GET", url, headers={"Origin": origin})
        prep = session.prepare_request(req)
        resp = session.send(prep, timeout=timeout, allow_redirects=True)
        ms   = (time.time() - t0) * 1000
        req_s  = _format_request(prep)
        acao   = resp.headers.get("Access-Control-Allow-Origin", "")
        acac   = resp.headers.get("Access-Control-Allow-Credentials", "")
        hdr_dump = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        resp_s = f"HTTP/1.1 {resp.status_code} {resp.reason}\n{hdr_dump}"
        if acao in (origin, "*"):
            note = (
                f"CONFIRMED: ACAO reflects `{acao}`"
                + (" with credentials=true — HIGH risk!" if acac.lower() == "true" else "")
            )
            finding["with_credentials"] = (acac.lower() == "true")
            return _confirm(note, req_s, resp_s, resp.status_code, ms)
        return _reject(f"ACAO is `{acao or '(absent)'}` — does not reflect the evil origin.")
    except Exception as exc:
        return _likely(f"Could not reach `{url}`: {exc}")


def _validate_open_redirect(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url   = finding.get("url", "")
    param = finding.get("param", "")
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    target_domain = "evil-validator-check.com"
    evil     = f"https://{target_domain}/proof"
    test_url = _inject_param(url, param, evil) if param else url + f"?next={evil}"
    try:
        t0   = time.time()
        req  = requests.Request("GET", test_url)
        prep = session.prepare_request(req)
        resp = session.send(prep, timeout=timeout, allow_redirects=False)
        ms   = (time.time() - t0) * 1000
        req_s    = _format_request(prep)
        location = resp.headers.get("Location", "")
        hdr_dump = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        resp_s   = f"HTTP/1.1 {resp.status_code} {resp.reason}\n{hdr_dump}"
        if target_domain in location and resp.status_code in (301, 302, 303, 307, 308):
            return _confirm(
                f"Confirmed: redirects to `{location}` (attacker-controlled domain).",
                req_s, resp_s, resp.status_code, ms
            )
        return _reject(f"Location: `{location or '(none)'}` — redirect did not follow payload.")
    except Exception as exc:
        return _likely(f"Could not reach `{url}`: {exc}")


def _validate_xss(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url     = finding.get("url", "")
    param   = finding.get("param", "")
    payload = finding.get("payload", "")
    method  = (finding.get("method") or "GET").upper()
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    payloads_to_try = [payload] if payload else _XSS_PAYLOADS[:2]
    for pl in payloads_to_try:
        try:
            t0       = time.time()
            test_url = _inject_param(url, param, pl) if param else url
            req      = requests.Request(method, test_url)
            prep     = session.prepare_request(req)
            resp     = session.send(prep, timeout=timeout, allow_redirects=True)
            ms       = (time.time() - t0) * 1000
            req_s    = _format_request(prep)
            # XSS requires an HTML execution context — reject non-HTML responses
            ct = resp.headers.get("Content-Type", "").lower()
            if ct and "text/html" not in ct:
                return _reject(
                    f"Response Content-Type is `{ct}` — payload cannot execute as XSS in a non-HTML context. "
                    "This is a false positive; the reflection is inside JSON/XML/text."
                )
            body = resp.text
            # Check for HTML-encoded variants first — if encoded, it's not exploitable
            encoded = pl.replace("<", "&lt;").replace(">", "&gt;")
            if encoded in body and pl not in body:
                return _reject(
                    f"Payload is HTML-encoded in the response (`{encoded[:60]}`) — not exploitable XSS."
                )
            for indicator in [pl, "<script>", "onerror=", "javascript:"]:
                if indicator in body:
                    resp_s = _format_response(resp, highlight_pattern=indicator)
                    return _confirm(
                        f"XSS payload `{indicator}` found UNESCAPED in HTML response — verify execution in a browser.",
                        req_s, resp_s, resp.status_code, ms
                    )
        except Exception:
            continue
    return _likely(
        "Could not confirm reflection in a quick re-test. "
        "Verify with Burp Suite — payload may only trigger in a real browser context."
    )


def _validate_sqli(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url     = finding.get("url", "")
    param   = finding.get("param", "")
    payload = finding.get("payload", "'")
    method  = (finding.get("method") or "GET").upper()
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    for pl in [payload, "'", '"', "' OR '1'='1"]:
        try:
            t0       = time.time()
            test_url = _inject_param(url, param, pl) if param else url
            req      = requests.Request(method, test_url)
            prep     = session.prepare_request(req)
            resp     = session.send(prep, timeout=timeout, allow_redirects=True)
            ms       = (time.time() - t0) * 1000
            req_s    = _format_request(prep)
            match    = _SQL_ERROR_PATTERNS.search(resp.text)
            if match:
                resp_s = _format_response(resp, highlight_pattern=match.group(0))
                return _confirm(
                    f"SQL error found in response: `{match.group(0)[:120]}`",
                    req_s, resp_s, resp.status_code, ms
                )
        except Exception:
            continue
    return _likely(
        "No SQL error triggered in re-test. "
        "May be blind SQLi — use time-based payloads or sqlmap for confirmation."
    )


def _validate_lfi(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url     = finding.get("url", "")
    param   = finding.get("param", "")
    payload = finding.get("payload", "../../../../etc/passwd")
    method  = (finding.get("method") or "GET").upper()
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    for pl in [payload, "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]:
        try:
            t0       = time.time()
            test_url = _inject_param(url, param, pl) if param else url
            req      = requests.Request(method, test_url)
            prep     = session.prepare_request(req)
            resp     = session.send(prep, timeout=timeout, allow_redirects=True)
            ms       = (time.time() - t0) * 1000
            req_s    = _format_request(prep)
            match    = _LFI_PATTERNS.search(resp.text)
            if match:
                resp_s = _format_response(resp, highlight_pattern=match.group(0))
                return _confirm(
                    f"File content confirmed in response: `{match.group(0)[:80]}`",
                    req_s, resp_s, resp.status_code, ms
                )
        except Exception:
            continue
    return _likely(
        "File content pattern not found in re-test. "
        "May require specific traversal depth or encoding — verify manually."
    )


def _validate_sensitive_file(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session = _get_session(ignore_ssl)
    url     = finding.get("url", "")
    if not url:
        return _likely("No URL in finding — could not re-validate.")
    try:
        t0   = time.time()
        req  = requests.Request("GET", url)
        prep = session.prepare_request(req)
        resp = session.send(prep, timeout=timeout, allow_redirects=True)
        ms   = (time.time() - t0) * 1000
        req_s = _format_request(prep)
        if resp.status_code in (401, 403, 404):
            return _reject(f"HTTP {resp.status_code} — file is no longer accessible.")
        match = _SENSITIVE_FILE_PATTERNS.search(resp.text)
        if match:
            resp_s = _format_response(resp, highlight_pattern=match.group(0))
            return _confirm(
                f"Sensitive content confirmed: `{match.group(0)[:80]}`",
                req_s, resp_s, resp.status_code, ms
            )
        resp_s = _format_response(resp)
        return _confirm(
            f"File accessible (HTTP {resp.status_code}) — review content manually.",
            req_s, resp_s, resp.status_code, ms
        )
    except Exception as exc:
        return _likely(f"Could not reach `{url}`: {exc}")


def _validate_subdomain_takeover(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    session   = _get_session(ignore_ssl)
    subdomain = finding.get("subdomain", finding.get("url", ""))
    if not subdomain:
        return _likely("No subdomain in finding — could not re-validate.")
    host = subdomain.split("//")[-1].split("/")[0]
    dns_note = ""
    try:
        import dns.resolver
        answers  = dns.resolver.resolve(host, "CNAME")
        cname    = str(answers[0].target).rstrip(".")
        dns_note = f"CNAME: {host} → {cname}"
    except Exception as exc:
        dns_note = f"DNS: {exc}"
    url = subdomain if subdomain.startswith("http") else f"https://{subdomain}"
    try:
        t0   = time.time()
        req  = requests.Request("GET", url)
        prep = session.prepare_request(req)
        resp = session.send(prep, timeout=timeout, allow_redirects=True)
        ms   = (time.time() - t0) * 1000
        req_s = _format_request(prep)
        for service, pattern in _TAKEOVER_SIGNATURES.items():
            m = pattern.search(resp.text)
            if m:
                resp_s = _format_response(resp, highlight_pattern=m.group(0))
                return _confirm(
                    f"Takeover confirmed via {service}: `{m.group(0)[:80]}`\n{dns_note}",
                    req_s, resp_s, resp.status_code, ms
                )
        resp_s = _format_response(resp)
        return _likely(
            f"Subdomain reachable (HTTP {resp.status_code}) but no known takeover signature. {dns_note}",
            req_s, resp_s
        )
    except Exception as exc:
        if dns_note:
            return _likely(f"Domain unreachable (possible takeover). {dns_note}\nHTTP error: {exc}")
        return _likely(f"Could not validate: {exc}")


def _validate_ssrf(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    url   = finding.get("url", "")
    param = finding.get("param", "")
    req_s = ""
    if url:
        try:
            session  = _get_session(ignore_ssl)
            test_url = _inject_param(url, param, "http://169.254.169.254/latest/meta-data/") if param else url
            req      = requests.Request("GET", test_url)
            prep     = session.prepare_request(req)
            req_s    = _format_request(prep)
        except Exception:
            pass
    return _likely(
        "SSRF cannot be safely validated without an OOB callback server. "
        "Use Burp Collaborator or https://app.interactsh.com — inject the URL into "
        "the parameter and check for DNS/HTTP callbacks.",
        request_str=req_s,
    )


def _validate_oob_only(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    ftype    = (finding.get("type") or "").lower()
    note_map = {
        "command injection":  "Command injection requires OOB confirmation. Use Burp Collaborator or interactsh.",
        "xxe":                "Blind XXE requires an OOB callback. Use Burp Collaborator or interactsh with a DTD that triggers HTTP/DNS.",
        "race condition":     "Race conditions require concurrent request timing. Use Burp Suite Turbo Intruder.",
        "idor":               "IDOR requires multiple test accounts. Re-test manually with two accounts.",
        "access control":     "Access control issues require an authenticated session. Re-test manually.",
        "broken access":      "Access control issues require an authenticated session. Re-test manually.",
        "authentication":     "Authentication bypass requires a live session. Re-test manually using Burp Suite.",
        "auth":               "Authentication bypass requires a live session. Re-test manually using Burp Suite.",
        "business logic":     "Business logic vulnerabilities require application-specific manual testing.",
        "file upload":        "File upload exploitation requires uploading a test file — not attempted automatically.",
        "http smuggling":     "HTTP Smuggling requires low-level TCP socket control. Use Burp Suite HTTP Request Smuggler.",
        "smuggling":          "HTTP Smuggling requires low-level TCP socket control. Use Burp Suite HTTP Request Smuggler.",
        "nosql":              "NoSQL injection requires database-specific payload tuning. Verify with NoSQLMap.",
        "web cache":          "Web cache poisoning requires CDN knowledge. Verify with Param Miner in Burp Suite.",
        "cache":              "Web cache poisoning requires CDN knowledge. Verify with Param Miner in Burp Suite.",
        "api":                "API endpoint vulnerabilities require authenticated requests. Re-test with valid API credentials.",
    }
    for key, note in note_map.items():
        if key in ftype:
            return _likely(note)
    return _likely(
        f"Automated confirmation not available for `{ftype}`. "
        "Verify this finding manually using Burp Suite or a similar proxy."
    )


_VALIDATOR_DISPATCH: list[tuple[str, object]] = [
    ("header",           _validate_missing_header),
    ("cors",             _validate_cors),
    ("redirect",         _validate_open_redirect),
    ("xss",              _validate_xss),
    ("sql",              _validate_sqli),
    ("sqli",             _validate_sqli),
    ("lfi",              _validate_lfi),
    ("path traversal",   _validate_lfi),
    ("sensitive",        _validate_sensitive_file),
    ("takeover",         _validate_subdomain_takeover),
    ("ssrf",             _validate_ssrf),
    ("xxe",              _validate_oob_only),
    ("command",          _validate_oob_only),
    ("smuggling",        _validate_oob_only),
    ("race",             _validate_oob_only),
    ("idor",             _validate_oob_only),
    ("access control",   _validate_oob_only),
    ("broken access",    _validate_oob_only),
    ("auth",             _validate_oob_only),
    ("business logic",   _validate_oob_only),
    ("file upload",      _validate_oob_only),
    ("nosql",            _validate_oob_only),
    ("web cache",        _validate_oob_only),
    ("cache",            _validate_oob_only),
    ("api",              _validate_oob_only),
]

_OOB_ONLY_TYPES = {
    "xxe", "command", "smuggling", "race", "idor",
    "access control", "broken access", "auth", "business logic",
    "file upload", "nosql", "web cache", "cache", "api",
}


def _is_oob_only(finding: dict) -> bool:
    ftype = (finding.get("type") or "").lower()
    return any(k in ftype for k in _OOB_ONLY_TYPES)


def _dispatch(finding: dict, ignore_ssl: bool, timeout: int) -> dict:
    ftype = (finding.get("type") or "").lower()
    for key, fn in _VALIDATOR_DISPATCH:
        if key in ftype:
            return fn(finding, ignore_ssl, timeout)  # type: ignore[operator]
    return _likely(f"No specific validator for type `{ftype}` — marked as unverified.")


def _all_findings(results: dict) -> list[dict]:
    found: list[dict] = []
    for section in ["header_issues", "cors_issues", "open_redirect_issues",
                     "xss_issues", "sqli_issues", "lfi_issues", "sensitive_files",
                     "http_method_issues"]:
        found.extend(results.get("vulns", {}).get(section, []))
    found.extend(results.get("takeover", {}).get("findings", []))
    found.extend(results.get("xss", {}).get("findings", []))
    found.extend(results.get("js", {}).get("converted_findings", []))
    found.extend(results.get("crawl", {}).get("path_findings", []))
    found.extend(results.get("cors_deep", {}).get("converted_findings", []))
    found.extend(results.get("smuggle", {}).get("converted_findings", []))
    found.extend(results.get("redirect", {}).get("converted_findings", []))
    found.extend(results.get("owasp", {}).get("summary", {}).get("all_findings", []))
    for adv_key in ["sqli", "auth", "pathtraversal", "cmdinject", "bizlogic",
                     "infodisclosure", "accesscontrol", "fileupload", "raceconditions",
                     "ssrf", "xxe", "nosqli", "apitest", "webcache"]:
        found.extend(results.get(adv_key, {}).get("findings", []))
    return found


def run(results: dict, timeout: int = _DEFAULT_TIMEOUT,
        ignore_ssl: bool = False, quiet: bool = False) -> dict:
    """Validate all findings in `results` in parallel.

    Adds to each finding dict:
        finding["confidence"]  = "confirmed" | "likely" | "rejected"
        finding["evidence"]    = {...}

    Returns a summary dict with confirmed/likely/rejected counts.
    """
    all_f = _all_findings(results)
    if not all_f:
        summary = {"confirmed": 0, "likely": 0, "rejected": 0, "total": 0, "rejected_findings": []}
        results["validation"] = summary
        return summary

    # Separate OOB-only findings (no I/O) from HTTP findings
    oob_findings  = [f for f in all_f if _is_oob_only(f)]
    http_findings = [f for f in all_f if not _is_oob_only(f)]

    # Deduplicate HTTP findings by (type, url) — same endpoint hit once, result shared
    _cache: dict[str, dict] = {}
    _canonical: dict[int, str] = {}
    canonical_http: list[dict] = []
    duplicate_http: list[tuple[dict, str]] = []

    for f in http_findings:
        url   = f.get("url", "") or ""
        ftype = (f.get("type") or "").lower().split("—")[0].strip()
        key   = f"{ftype}::{url}"
        _canonical[id(f)] = key
        if key not in _cache:
            _cache[key] = {}
            canonical_http.append(f)
        else:
            duplicate_http.append((f, key))

    # OOB findings: instant, no I/O
    for f in oob_findings:
        result          = _validate_oob_only(f, ignore_ssl, timeout)
        f["confidence"] = result.get("confidence", "likely")
        f["evidence"]   = result.get("evidence", {})

    # HTTP findings: parallel with per-thread session reuse
    max_workers = min(50, max(1, len(canonical_http)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_dispatch, f, ignore_ssl, timeout): f
            for f in canonical_http
        }
        for future in as_completed(futures):
            f      = futures[future]
            result = future.result()
            key    = _canonical[id(f)]
            _cache[key]     = result
            f["confidence"] = result.get("confidence", "likely")
            f["evidence"]   = result.get("evidence", {})

    # Apply cached results to duplicates (no extra requests)
    for f, key in duplicate_http:
        result          = _cache.get(key, {})
        f["confidence"] = result.get("confidence", "likely")
        f["evidence"]   = result.get("evidence", {})

    confirmed = 0
    likely    = 0
    rejected  = 0
    rejected_findings: list[dict] = []

    for f in all_f:
        c = f.get("confidence", "likely")
        if c == "confirmed":
            confirmed += 1
        elif c == "rejected":
            rejected += 1
            rejected_findings.append(f)
        else:
            likely += 1

    summary = {
        "confirmed":         confirmed,
        "likely":            likely,
        "rejected":          rejected,
        "total":             len(all_f),
        "rejected_findings": rejected_findings,
    }
    results["validation"] = summary
    return summary
