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
Deep CORS misconfiguration tester.
Tests 10 distinct origin bypass techniques across the homepage and all
crawled URLs, flags credential-bearing misconfigs as CRITICAL.
"""

import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"


# ── Origin bypass recipes ─────────────────────────────────────────────────────

def _build_origins(target_url: str) -> list[dict]:
    """
    Return a list of origin probe dicts for a given target URL.
    Each dict has:  label, origin, technique, expect_reflect (bool)
    """
    parsed   = urllib.parse.urlparse(target_url)
    scheme   = parsed.scheme          # "https"
    host     = parsed.netloc          # "example.com" or "example.com:443"
    bare     = host.split(":")[0]     # "example.com"
    alt_scheme = "http" if scheme == "https" else "https"

    # eTLD+1 approximation: last two segments
    parts      = bare.split(".")
    root       = ".".join(parts[-2:]) if len(parts) >= 2 else bare
    parent     = ".".join(parts[1:])  if len(parts) > 2  else root

    probes = [
        {
            "label":       "Arbitrary origin",
            "technique":   "Send a completely unrelated origin and check if it is reflected.",
            "origin":      "https://evil.com",
            "expect_reflect": True,
        },
        {
            "label":       "Null origin",
            "technique":   "Send 'Origin: null' (used by sandboxed iframes, file:// pages).",
            "origin":      "null",
            "expect_reflect": True,
        },
        {
            "label":       "HTTP downgrade",
            "technique":   f"Send the same origin over {alt_scheme}:// instead of {scheme}://.",
            "origin":      f"{alt_scheme}://{bare}",
            "expect_reflect": True,
        },
        {
            "label":       "Pre-domain bypass",
            "technique":   "Prefix the target domain on an attacker domain (evil.example.com trust confusion).",
            "origin":      f"{scheme}://evil.{root}",
            "expect_reflect": True,
        },
        {
            "label":       "Post-domain bypass",
            "technique":   "Suffix an attacker domain after the target domain (example.com.evil.com).",
            "origin":      f"{scheme}://{bare}.evil.com",
            "expect_reflect": True,
        },
        {
            "label":       "Wildcard prefix bypass",
            "technique":   "Prepend arbitrary chars to the target domain (notexample.com).",
            "origin":      f"{scheme}://not{root}",
            "expect_reflect": True,
        },
        {
            "label":       "Trusted subdomain",
            "technique":   "Legitimate-looking subdomain (sub.example.com) — tests overly broad wildcard allow.",
            "origin":      f"{scheme}://sub.{root}",
            "expect_reflect": True,
        },
        {
            "label":       "Parent domain",
            "technique":   "Parent domain (relevant when target is sub.parent.com).",
            "origin":      f"{scheme}://{parent}",
            "expect_reflect": True,
        },
        {
            "label":       "Origin with non-standard port",
            "technique":   "Same origin but with an unusual port number.",
            "origin":      f"{scheme}://{bare}:8080",
            "expect_reflect": True,
        },
        {
            "label":       "Unicode/special-char origin",
            "technique":   "Origin with underscore — tests weak regex-based allow-lists.",
            "origin":      f"{scheme}://{bare}_.evil.com",
            "expect_reflect": True,
        },
    ]
    return probes


# ── Single probe ──────────────────────────────────────────────────────────────

def _probe(
    url: str,
    probe: dict,
    timeout: int,
    user_agent: str,
) -> Optional[dict]:
    """Fire one CORS probe and return a result dict, or None on network error."""
    origin = probe["origin"]
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Origin":      origin,
                "User-Agent":  user_agent,
                "Accept":      "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        acam = headers.get("access-control-allow-methods", "")
        acah = headers.get("access-control-allow-headers", "")
        vary = headers.get("vary", "")

        reflected      = (acao == origin or (origin == "null" and acao == "null"))
        wildcard       = acao == "*"
        with_creds     = acac == "true"
        vary_origin    = "origin" in vary.lower()

        if not (reflected or wildcard):
            return None          # no misconfiguration for this probe

        # Severity matrix
        if (reflected or wildcard) and with_creds:
            severity = SEVERITY_CRITICAL
            impact   = "Attacker can make authenticated cross-origin requests and read responses (session hijack risk)."
        elif reflected:
            severity = SEVERITY_HIGH
            impact   = "Arbitrary origin is reflected — attacker can read cross-origin responses (no credentials)."
        else:  # wildcard, no creds
            severity = SEVERITY_MEDIUM
            impact   = "Wildcard ACAO allows any origin to read responses — fine for public APIs, bad for auth-gated endpoints."

        recommendation = (
            "Maintain an explicit server-side allowlist of trusted origins. "
            "Never reflect the incoming Origin header blindly. "
            "Never combine Access-Control-Allow-Credentials: true with a wildcard or reflected origin."
        )
        if not vary_origin:
            recommendation += " Also add 'Vary: Origin' to prevent cache poisoning."

        return {
            "url":             url,
            "label":           probe["label"],
            "technique":       probe["technique"],
            "origin_sent":     origin,
            "acao":            acao,
            "acac":            acac,
            "acam":            acam,
            "acah":            acah,
            "vary":            vary,
            "reflected":       reflected,
            "wildcard":        wildcard,
            "with_credentials": with_creds,
            "vary_missing":    not vary_origin,
            "severity":        severity,
            "impact":          impact,
            "recommendation":  recommendation,
        }

    except Exception:
        return None


# ── Preflight probe ───────────────────────────────────────────────────────────

def _preflight(url: str, origin: str, timeout: int, user_agent: str) -> Optional[dict]:
    """Send an OPTIONS preflight and return the CORS headers."""
    try:
        req = urllib.request.Request(
            url,
            method="OPTIONS",
            headers={
                "Origin":                         origin,
                "Access-Control-Request-Method":  "GET",
                "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                "User-Agent":                     user_agent,
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "status":  resp.status,
                "acao":    headers.get("access-control-allow-origin", ""),
                "acac":    headers.get("access-control-allow-credentials", ""),
                "acam":    headers.get("access-control-allow-methods", ""),
                "acah":    headers.get("access-control-allow-headers", ""),
                "acma":    headers.get("access-control-max-age", ""),
            }
    except Exception:
        return None


# ── Public scan entry point ───────────────────────────────────────────────────

def scan_cors(
    base_url: str,
    extra_urls: Optional[list[str]] = None,
    threads: int = 10,
    timeout: int = 8,
    user_agent: str = "BugBountyTool/1.0",
    max_urls: int = 20,
) -> dict:
    """
    Run all 10 CORS bypass probes against base_url + up to max_urls crawled URLs.

    Returns:
      findings:       list of vuln dicts (de-duped by technique)
      url_results:    per-URL probe breakdown (for report table)
      preflight:      OPTIONS result for base_url
      summary:        counts
    """
    # Dedupe + cap the URL list
    target_urls = [base_url]
    seen = {base_url}
    for u in (extra_urls or []):
        parsed = urllib.parse.urlparse(u)
        # Only test HTML pages, not assets
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".gif", ".woff", ".ico")):
            continue
        if u not in seen:
            seen.add(u)
            target_urls.append(u)
        if len(target_urls) >= max_urls:
            break

    probes = _build_origins(base_url)

    # Build all (url, probe) jobs
    jobs = [(url, probe) for url in target_urls for probe in probes]

    raw_results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe, url, probe, timeout, user_agent): (url, probe)
            for url, probe in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                raw_results.append(result)

    # Preflight check on base_url with arbitrary origin
    preflight_result = _preflight(base_url, "https://evil.com", timeout, user_agent)

    # De-dupe findings by (technique_label, url) — keep highest severity
    seen_keys: dict[str, dict] = {}
    for r in raw_results:
        key = f"{r['label']}::{r['url']}"
        if key not in seen_keys:
            seen_keys[key] = r
        else:
            sev_order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3, SEVERITY_INFO: 4}
            if sev_order.get(r["severity"], 9) < sev_order.get(seen_keys[key]["severity"], 9):
                seen_keys[key] = r

    findings = sorted(
        seen_keys.values(),
        key=lambda x: {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2,
                       SEVERITY_LOW: 3, SEVERITY_INFO: 4}.get(x["severity"], 9),
    )

    # Build a per-URL summary (which techniques fired per URL)
    url_summary: dict[str, list] = {}
    for f in findings:
        url_summary.setdefault(f["url"], []).append(f)

    critical_count = sum(1 for f in findings if f["severity"] == SEVERITY_CRITICAL)
    high_count     = sum(1 for f in findings if f["severity"] == SEVERITY_HIGH)
    creds_count    = sum(1 for f in findings if f.get("with_credentials"))

    return {
        "findings":       findings,
        "url_results":    url_summary,
        "preflight":      preflight_result,
        "urls_tested":    target_urls,
        "summary": {
            "urls_tested":    len(target_urls),
            "probes_fired":   len(jobs),
            "findings_total": len(findings),
            "critical":       critical_count,
            "high":           high_count,
            "with_creds":     creds_count,
        },
    }


def as_findings(cors_results: dict) -> list[dict]:
    """Convert CORS scan results to the flat findings format used by reporter."""
    out = []
    for f in cors_results.get("findings", []):
        out.append({
            "type":           f"CORS — {f['label']}",
            "severity":       f["severity"],
            "url":            f["url"],
            "description":    (
                f"{f['label']}: sent Origin: {f['origin_sent']} → "
                f"ACAO: {f['acao']}"
                + (" | credentials=true" if f.get("with_credentials") else "")
            ),
            "recommendation": f["recommendation"],
            "impact":         f.get("impact", ""),
        })
    return out


if __name__ == "__main__":
    pass
