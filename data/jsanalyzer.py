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
Passive JavaScript file analyzer.
Fetches all JS files and hunts for exposed secrets, API keys,
internal endpoints, and dangerous DOM sinks.
"""

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


SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID",        SEVERITY_CRITICAL, r'(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
    ("AWS Secret Access Key",    SEVERITY_CRITICAL, r'(?:aws[_\-\s]?secret|aws[_\-\s]?key)[^=\n]{0,30}=\s*["\']?([A-Za-z0-9/+]{40})["\']?'),
    # Google
    ("Google API Key",           SEVERITY_HIGH,     r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google OAuth Client ID",   SEVERITY_MEDIUM,   r'[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com'),
    ("Firebase Config",          SEVERITY_MEDIUM,   r'firebase[^{]{0,50}\{[^}]{0,300}apiKey[^}]{0,300}\}'),
    # Auth tokens
    ("GitHub Token",             SEVERITY_CRITICAL, r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
    ("GitHub Classic Token",     SEVERITY_CRITICAL, r'github_pat_[A-Za-z0-9_]{82}'),
    ("Slack Token",              SEVERITY_CRITICAL, r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}'),
    ("Slack Webhook",            SEVERITY_HIGH,     r'https://hooks\.slack\.com/services/[A-Za-z0-9_/+]{40,}'),
    # Stripe
    ("Stripe Secret Key",        SEVERITY_CRITICAL, r'sk_live_[0-9a-zA-Z]{24,}'),
    ("Stripe Publishable Key",   SEVERITY_INFO,     r'pk_live_[0-9a-zA-Z]{24,}'),
    ("Stripe Test Key",          SEVERITY_LOW,      r'sk_test_[0-9a-zA-Z]{24,}'),
    # Twilio
    ("Twilio Account SID",       SEVERITY_HIGH,     r'AC[a-f0-9]{32}'),
    ("Twilio Auth Token",        SEVERITY_CRITICAL, r'twilio[^=\n]{0,30}=\s*["\']([a-f0-9]{32})["\']'),
    # Sendgrid / Mailgun
    ("SendGrid API Key",         SEVERITY_HIGH,     r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
    ("Mailgun API Key",          SEVERITY_HIGH,     r'key-[0-9a-f]{32}'),
    # JWT
    ("JWT Token",                SEVERITY_HIGH,     r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'),
    # Private keys
    ("RSA Private Key",          SEVERITY_CRITICAL, r'-----BEGIN RSA PRIVATE KEY-----'),
    ("Private Key",              SEVERITY_CRITICAL, r'-----BEGIN (?:EC|DSA|OPENSSH) PRIVATE KEY-----'),
    # Password-like
    ("Hardcoded Password",       SEVERITY_HIGH,     r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\'][^"\']{6,}["\']'),
    ("Hardcoded Secret",         SEVERITY_HIGH,     r'(?:secret|secret_key|secretKey)\s*[:=]\s*["\'][^"\']{8,}["\']'),
    ("Hardcoded Token",          SEVERITY_HIGH,     r'(?:token|auth_token|authToken|access_token|accessToken)\s*[:=]\s*["\'][^"\']{10,}["\']'),
    ("Bearer Token",             SEVERITY_MEDIUM,   r'[Bb]earer\s+[A-Za-z0-9\-_]{20,}'),
    # Cloud / DB connection strings
    ("MongoDB URI",              SEVERITY_CRITICAL, r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}'),
    ("PostgreSQL URI",           SEVERITY_CRITICAL, r'postgres(?:ql)?://[^\s"\'<>]{10,}'),
    ("MySQL URI",                SEVERITY_CRITICAL, r'mysql://[^\s"\'<>]{10,}'),
    ("Redis URI",                SEVERITY_HIGH,     r'redis://[^\s"\'<>]{10,}'),
    ("SMTP URI",                 SEVERITY_MEDIUM,   r'smtps?://[^\s"\'<>]{10,}'),
    # Azure
    ("Azure Storage Key",        SEVERITY_CRITICAL, r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;'),
    ("Azure SAS Token",          SEVERITY_HIGH,     r'[?&]se=[0-9TZ%]+&spr=https&sv=[0-9\-]+&sr=[a-z]+&sig=[A-Za-z0-9%+=]{40,}'),
    # Misc
    ("Heroku API Key",           SEVERITY_HIGH,     r'[hH]eroku[^=\n]{0,30}=\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']'),
    ("NPM Token",                SEVERITY_HIGH,     r'npm_[A-Za-z0-9]{36}'),
    ("Cloudinary URL",           SEVERITY_MEDIUM,   r'cloudinary://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+'),
    ("Mapbox Token",             SEVERITY_MEDIUM,   r'pk\.eyJ1[A-Za-z0-9\-_\.]+\.eyJ[A-Za-z0-9\-_\.]+'),
]


ENDPOINT_PATTERNS = [
    r'["\'`](/(?:api|v\d|graphql|rest|endpoint|rpc|admin)[^\s"\'`<>]{2,100})["\' `]',
    r'["\'`]((?:https?://|//)[^\s"\'`<>]{5,100})["\' `]',
    r'url\s*[:=]\s*["\']([^"\']{5,150})["\']',
    r'(?:fetch|axios\.get|axios\.post|http\.get|\.ajax)\s*\(\s*["\']([^"\']{5,150})["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']{5,150})["\']',
    r'(?:baseURL|baseUrl|BASE_URL|ApiUrl|API_URL)\s*[:=]\s*["\']([^"\']{5,150})["\']',
]

SINK_PATTERNS = [
    ("eval()",                   SEVERITY_HIGH,     r'eval\s*\((?!\s*["\']use strict["\'])'),
    ("innerHTML assignment",     SEVERITY_HIGH,     r'\.innerHTML\s*[+]?=\s*(?![\s]*["\'][^<>]*["\'])'),
    ("document.write()",         SEVERITY_HIGH,     r'document\.write\s*\('),
    ("outerHTML assignment",     SEVERITY_MEDIUM,   r'\.outerHTML\s*[+]?='),
    ("insertAdjacentHTML()",     SEVERITY_MEDIUM,   r'insertAdjacentHTML\s*\('),
    ("dangerouslySetInnerHTML",  SEVERITY_HIGH,     r'dangerouslySetInnerHTML\s*=\s*\{'),
    ("setTimeout with string",   SEVERITY_MEDIUM,   r'setTimeout\s*\(\s*(?:["\'])'),
    ("setInterval with string",  SEVERITY_MEDIUM,   r'setInterval\s*\(\s*(?:["\'])'),
    ("location.href injection",  SEVERITY_HIGH,     r'location\.href\s*=\s*(?![\s]*["\'][^<>]*["\'])'),
    ("window.open() injection",  SEVERITY_MEDIUM,   r'window\.open\s*\(\s*(?![\s]*["\'][^<>]*["\'])'),
    ("postMessage without origin check", SEVERITY_MEDIUM, r'addEventListener\s*\(\s*["\']message["\'].*\)(?:(?!origin).){0,200}function'),
    ("document.domain",          SEVERITY_HIGH,     r'document\.domain\s*='),
    ("Function() constructor",   SEVERITY_HIGH,     r'new\s+Function\s*\('),
    ("__proto__ modification",   SEVERITY_CRITICAL, r'(?:__proto__|constructor\[prototype\])\s*(?:\[|\.)\s*\w+\s*[+]?='),
]

COMMENT_PATTERNS = [
    (r'//\s*(?:TODO|FIXME|HACK|BUG|XXX|TEMP|WORKAROUND)[^\n]{0,200}', SEVERITY_LOW, "Developer comment"),
    (r'//\s*(?:password|secret|key|token|cred)[^\n]{0,200}', SEVERITY_HIGH, "Credential comment"),
    (r'/\*[\s\S]{0,50}(?:internal|admin|debug|test|staging)[^\*]{0,200}\*/', SEVERITY_LOW, "Internal reference comment"),
]

SOURCE_MAP_PATTERN = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(.+\.map)', re.IGNORECASE)


def _extract_js_urls(page_response: dict, base_url: str, discovered_dirs: list[dict]) -> list[str]:
    body = page_response.get("body", "")
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
    js_urls = set()

    src_matches = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        body, re.IGNORECASE
    )
    for src in src_matches:
        if src.startswith("//"):
            js_urls.add("https:" + src)
        elif src.startswith("/"):
            js_urls.add(base_domain + src)
        elif src.startswith("http"):
            js_urls.add(src)
        else:
            js_urls.add(base_url.rstrip("/") + "/" + src)

    for d in (discovered_dirs or []):
        url = d.get("url", "")
        if url.endswith(".js") and d.get("status") == 200:
            js_urls.add(url)

    return list(js_urls)


def _fetch_js(url: str, timeout: int, ua: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read(500_000).decode("utf-8", errors="replace")
            return {
                "url": url,
                "body": body,
                "size": len(body),
                "content_type": content_type,
            }
    except Exception:
        return None


def _redact(value: str) -> str:
    if len(value) <= 12:
        return value[:3] + "***"
    return value[:6] + "..." + value[-4:]


def scan_js_file(js: dict, source_base: str) -> dict:
    url  = js["url"]
    body = js["body"]

    secrets    = []
    endpoints  = []
    sinks      = []
    comments   = []
    source_maps = []

    for name, severity, pattern in SECRET_PATTERNS:
        matches = re.finditer(pattern, body)
        seen = set()
        for m in matches:
            full  = m.group(0)
            inner = m.group(1) if m.lastindex else full
            if inner in seen:
                continue
            seen.add(inner)
            line_num = body[:m.start()].count("\n") + 1
            excerpt  = body[max(0, m.start() - 40): m.end() + 20].strip()
            secrets.append({
                "type":            name,
                "severity":        severity,
                "value_redacted":  _redact(inner),
                "line":            line_num,
                "excerpt":         re.sub(r'\s+', ' ', excerpt)[:120],
                "js_file":         url,
            })

    seen_endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, body):
            ep = m.group(1)
            if ep in seen_endpoints:
                continue
            seen_endpoints.add(ep)
            if any(skip in ep for skip in ["localhost", "127.0.0.1", "example.com", "{", "${"]):
                continue
            parsed = urllib.parse.urlparse(ep)
            if parsed.scheme and parsed.scheme not in ("http", "https", ""):
                continue
            line_num = body[:m.start()].count("\n") + 1
            endpoints.append({
                "endpoint": ep,
                "line":     line_num,
                "js_file":  url,
            })

    for name, severity, pattern in SINK_PATTERNS:
        for m in re.finditer(pattern, body, re.DOTALL):
            line_num  = body[:m.start()].count("\n") + 1
            ctx_start = max(0, m.start() - 60)
            ctx_end   = min(len(body), m.end() + 60)
            excerpt   = re.sub(r'\s+', ' ', body[ctx_start:ctx_end]).strip()
            sinks.append({
                "type":     name,
                "severity": severity,
                "line":     line_num,
                "excerpt":  excerpt[:150],
                "js_file":  url,
            })

    for pattern, severity, label in COMMENT_PATTERNS:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            line_num = body[:m.start()].count("\n") + 1
            text     = m.group(0).strip()[:200]
            comments.append({
                "type":     label,
                "severity": severity,
                "line":     line_num,
                "text":     text,
                "js_file":  url,
            })

    for m in SOURCE_MAP_PATTERN.finditer(body):
        map_url = m.group(1).strip()
        if not map_url.startswith("http"):
            base_dir = url.rsplit("/", 1)[0]
            map_url  = base_dir + "/" + map_url
        source_maps.append({
            "map_url":     map_url,
            "js_file":     url,
            "severity":    SEVERITY_MEDIUM,
            "description": "Source map reference found — may expose original TypeScript/source code",
        })

    return {
        "url":         url,
        "size":        js["size"],
        "secrets":     secrets,
        "endpoints":   endpoints,
        "sinks":       sinks,
        "comments":    comments,
        "source_maps": source_maps,
    }


def analyze_js_files(
    base_url: str,
    page_response: Optional[dict],
    discovered_dirs: list[dict],
    threads: int = 10,
    timeout: int = 10,
    user_agent: str = "BugBountyTool/1.0",
) -> dict:
    if not page_response:
        return {"files_scanned": [], "summary": {}}

    js_urls = _extract_js_urls(page_response, base_url, discovered_dirs)
    if not js_urls:
        return {"files_scanned": [], "summary": {}}

    # Phase 1: fetch all JS files in parallel
    fetched: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_fetch_js, url, timeout, user_agent): url for url in js_urls}
        for future in as_completed(futures):
            result = future.result()
            if result:
                fetched.append(result)

    if not fetched:
        return {"files_scanned": [], "summary": {}}

    parsed_base = urllib.parse.urlparse(base_url)
    source_base = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # Phase 2: analyze all fetched JS files in parallel (CPU-bound regex work)
    scanned:         list[dict] = []
    all_secrets:     list[dict] = []
    all_endpoints:   list[dict] = []
    all_sinks:       list[dict] = []
    all_source_maps: list[dict] = []

    with ThreadPoolExecutor(max_workers=min(threads, len(fetched))) as executor:
        futures = {executor.submit(scan_js_file, js, source_base): js for js in fetched}
        for future in as_completed(futures):
            analysis = future.result()
            scanned.append(analysis)
            all_secrets.extend(analysis["secrets"])
            all_endpoints.extend(analysis["endpoints"])
            all_sinks.extend(analysis["sinks"])
            all_source_maps.extend(analysis["source_maps"])

    all_endpoints = _dedupe_endpoints(all_endpoints)

    summary = {
        "files_scanned":    len(scanned),
        "total_secrets":    len(all_secrets),
        "total_endpoints":  len(all_endpoints),
        "total_sinks":      len(all_sinks),
        "total_source_maps": len(all_source_maps),
    }

    return {
        "files_scanned":  scanned,
        "all_secrets":    all_secrets,
        "all_endpoints":  all_endpoints,
        "all_sinks":      all_sinks,
        "all_source_maps": all_source_maps,
        "summary":        summary,
    }


def _dedupe_endpoints(endpoints: list[dict]) -> list[dict]:
    seen = set()
    out  = []
    for e in endpoints:
        ep = e["endpoint"]
        if ep not in seen:
            seen.add(ep)
            out.append(e)
    return sorted(out, key=lambda x: x["endpoint"])


def as_findings(js_results: dict) -> list[dict]:
    findings = []

    for s in js_results.get("all_secrets", []):
        findings.append({
            "type":           f"Exposed Secret — {s['type']}",
            "severity":       s["severity"],
            "description":    f"{s['type']} found in {s['js_file'].split('/')[-1]} (line {s['line']}): {s['value_redacted']}",
            "url":            s["js_file"],
            "excerpt":        s.get("excerpt", ""),
            "recommendation": "Remove hardcoded credentials from client-side JavaScript. Use server-side secrets management.",
        })

    for sk in js_results.get("all_sinks", []):
        findings.append({
            "type":           f"Dangerous DOM Sink — {sk['type']}",
            "severity":       sk["severity"],
            "description":    f"{sk['type']} found in {sk['js_file'].split('/')[-1]} (line {sk['line']})",
            "url":            sk["js_file"],
            "excerpt":        sk.get("excerpt", ""),
            "recommendation": "Avoid dangerous DOM APIs with user-controlled input. Use textContent, safe frameworks, or DOMPurify.",
        })

    for sm in js_results.get("all_source_maps", []):
        findings.append({
            "type":           "Source Map Exposed",
            "severity":       sm["severity"],
            "description":    sm["description"],
            "url":            sm["map_url"],
            "recommendation": "Disable source map generation in production builds or serve them only to authenticated users.",
        })

    return findings


if __name__ == "__main__":
    pass
