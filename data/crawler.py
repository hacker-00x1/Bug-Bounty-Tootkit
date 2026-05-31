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
Passive internal-link crawler.
Follows same-origin (or same-root-domain) links up to a configurable depth,
respects robots.txt, applies per-host rate limiting, and collects all
unique URLs, JS files, forms, and params for downstream scanners.
"""

import re
import time
import threading
import urllib.parse
import urllib.request
import urllib.error
import urllib.robotparser
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


_TAG_HREF   = re.compile(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
_TAG_FORM   = re.compile(r'<form[^>]+action=["\']([^"\']*)["\']', re.IGNORECASE)
_TAG_SCRIPT = re.compile(r'<script[^>]+src=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE)
_META_REFRESH = re.compile(r'content=["\'][^"\']*url=([^"\';\s]+)', re.IGNORECASE)
_INPUT_PARAM  = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)
_SELECT_PARAM = re.compile(r'<select[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)
_TEXTAREA_PARAM = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)


# ── Robots.txt cache ──────────────────────────────────────────────────────────

_robots_cache: dict[str, urllib.robotparser.RobotFileParser] = {}
_robots_lock = threading.Lock()


def _get_robots(scheme: str, host: str, timeout: int, ua: str) -> urllib.robotparser.RobotFileParser:
    key = f"{scheme}://{host}"
    with _robots_lock:
        if key in _robots_cache:
            return _robots_cache[key]
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(f"{key}/robots.txt")
    try:
        req = urllib.request.Request(f"{key}/robots.txt", headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read(65536).decode("utf-8", errors="replace")
        rp.parse(content.splitlines())
    except Exception:
        rp.parse([])
    with _robots_lock:
        _robots_cache[key] = rp
    return rp


def _robots_allowed(url: str, timeout: int, ua: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    rp = _get_robots(parsed.scheme, parsed.netloc, timeout, ua)
    return rp.can_fetch(ua, url)


# ── Per-host rate limiter ─────────────────────────────────────────────────────

class _RateLimiter:
    """Thread-safe per-host delay enforcer."""

    def __init__(self, delay_ms: int):
        self._delay = delay_ms / 1000.0
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self._delay <= 0:
            return
        with self._lock:
            last = self._last.get(host, 0.0)
            now = time.monotonic()
            gap = self._delay - (now - last)
            if gap > 0:
                time.sleep(gap)
            self._last[host] = time.monotonic()


# ── Scope check ──────────────────────────────────────────────────────────────

def _root_domain(host: str) -> str:
    """Return eTLD+1 approximation: last two dot-segments."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _in_scope(url: str, origin_host: str, allow_subdomains: bool) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.netloc
    if not allow_subdomains:
        return host == origin_host
    return _root_domain(host) == _root_domain(origin_host)


# ── URL normalisation ─────────────────────────────────────────────────────────

def _normalize(
    raw: str,
    base: str,
    origin_host: str,
    allow_subdomains: bool,
) -> Optional[str]:
    raw = raw.strip()
    if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    resolved = urllib.parse.urljoin(base, raw)
    if not _in_scope(resolved, origin_host, allow_subdomains):
        return None
    parsed = urllib.parse.urlparse(resolved)
    return parsed._replace(fragment="").geturl()


# ── Page fetch ────────────────────────────────────────────────────────────────

def _fetch_page(
    url: str,
    timeout: int,
    ua: str,
    rate_limiter: _RateLimiter,
    respect_robots: bool,
) -> Optional[dict]:
    if respect_robots and not _robots_allowed(url, timeout, ua):
        return {"url": url, "status": 0, "body": "", "blocked_by_robots": True}

    host = urllib.parse.urlparse(url).netloc
    rate_limiter.wait(host)

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" not in ct and "text/plain" not in ct:
                return None
            body = resp.read(300_000).decode("utf-8", errors="replace")
            return {
                "url": resp.geturl(),
                "status": resp.status,
                "body": body,
                "content_type": ct,
                "blocked_by_robots": False,
            }
    except Exception:
        return None


# ── Link / form extraction ────────────────────────────────────────────────────

def _extract_links(
    body: str,
    page_url: str,
    origin_host: str,
    allow_subdomains: bool,
) -> dict:
    links: set[str] = set()
    js_files: set[str] = set()
    forms: list[dict] = []

    def norm(raw: str) -> Optional[str]:
        return _normalize(raw, page_url, origin_host, allow_subdomains)

    for m in _TAG_HREF.finditer(body):
        n = norm(m.group(1))
        if n:
            links.add(n)

    for m in _META_REFRESH.finditer(body):
        n = norm(m.group(1))
        if n:
            links.add(n)

    for m in _TAG_FORM.finditer(body):
        action_raw = m.group(1)
        action = norm(action_raw) or page_url
        # extract all field names from this form's section
        form_start = m.start()
        form_end_m = re.search(r'</form>', body[form_start:], re.IGNORECASE)
        form_body = body[form_start: form_start + form_end_m.end()] if form_end_m else body[form_start:]
        params = list(set(
            _INPUT_PARAM.findall(form_body)
            + _SELECT_PARAM.findall(form_body)
            + _TEXTAREA_PARAM.findall(form_body)
        ))
        forms.append({
            "action": action,
            "params": params,
            "method": "POST" if re.search(r'method=["\']?post', body[form_start:form_start+200], re.IGNORECASE) else "GET",
        })
        n = norm(action_raw)
        if n:
            links.add(n)

    for m in _TAG_SCRIPT.finditer(body):
        n = norm(m.group(1))
        if n:
            js_files.add(n)

    return {"links": links, "js_files": js_files, "forms": forms}


# ── Robots.txt public helper ──────────────────────────────────────────────────

def fetch_robots_txt(base_url: str, timeout: int = 8, ua: str = "BugBountyTool/1.0") -> dict:
    """Fetch and parse robots.txt, returning disallowed paths and sitemap hints."""
    parsed = urllib.parse.urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        req = urllib.request.Request(robots_url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return {"url": robots_url, "found": False, "raw": "", "disallowed": [], "sitemaps": []}

    disallowed: list[str] = []
    sitemaps: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                disallowed.append(path)
        elif line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)

    return {
        "url": robots_url,
        "found": True,
        "raw": raw,
        "disallowed": disallowed,
        "sitemaps": sitemaps,
    }


# ── Main crawl ────────────────────────────────────────────────────────────────

def crawl(
    start_url: str,
    max_depth: int = 2,
    max_pages: int = 60,
    threads: int = 10,
    timeout: int = 8,
    user_agent: str = "BugBountyTool/1.0",
    delay_ms: int = 0,
    respect_robots: bool = True,
    allow_subdomains: bool = False,
) -> dict:
    """
    BFS crawl from start_url.

    Parameters
    ----------
    delay_ms        Milliseconds to wait between requests to the same host
                    (0 = no rate limiting).
    respect_robots  When True, disallowed URLs (per robots.txt) are skipped.
    allow_subdomains
                    When True, crawl extends to subdomains sharing the same
                    root domain (e.g. blog.example.com when target is example.com).

    Returns a dict with keys:
      pages, all_urls, all_js_files, all_forms, all_params,
      robots_txt, blocked_by_robots, summary
    """
    origin = urllib.parse.urlparse(start_url)
    origin_host = origin.netloc

    rate_limiter = _RateLimiter(delay_ms)

    # Fetch + cache robots.txt up front so the report can show it
    robots_info = fetch_robots_txt(start_url, timeout=timeout, ua=user_agent)

    visited: set[str] = set()
    queued: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    blocked_urls: list[str] = []

    queue.append((start_url, 0))
    queued.add(start_url)

    pages: list[dict] = []
    all_urls: set[str] = {start_url}
    all_js_files: set[str] = set()
    all_forms: list[dict] = []
    all_params: set[str] = set()

    while queue and len(pages) < max_pages:
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < threads:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            batch.append((url, depth))

        if not batch:
            break

        with ThreadPoolExecutor(max_workers=min(threads, len(batch))) as executor:
            futures = {
                executor.submit(
                    _fetch_page, url, timeout, user_agent, rate_limiter, respect_robots
                ): (url, depth)
                for url, depth in batch
            }
            for future in as_completed(futures):
                url, depth = futures[future]
                result = future.result()
                if not result:
                    continue

                if result.get("blocked_by_robots"):
                    blocked_urls.append(url)
                    continue

                body = result["body"]
                extracted = _extract_links(body, result["url"], origin_host, allow_subdomains)

                pages.append({
                    "url": result["url"],
                    "depth": depth,
                    "status": result["status"],
                    "links_found": len(extracted["links"]),
                    "js_files": list(extracted["js_files"]),
                    "forms": extracted["forms"],
                })

                all_urls.update(extracted["links"])
                all_js_files.update(extracted["js_files"])
                all_forms.extend(extracted["forms"])

                parsed_url = urllib.parse.urlparse(result["url"])
                for key in urllib.parse.parse_qs(parsed_url.query):
                    all_params.add(key)

                if depth < max_depth:
                    for link in extracted["links"]:
                        if link not in queued and link not in visited:
                            queued.add(link)
                            queue.append((link, depth + 1))

        if len(pages) >= max_pages:
            break

    # Harvest query params from all discovered (not necessarily crawled) URLs
    for url in all_urls:
        parsed = urllib.parse.urlparse(url)
        for key in urllib.parse.parse_qs(parsed.query):
            all_params.add(key)

    return {
        "pages": pages,
        "all_urls": sorted(all_urls),
        "all_js_files": sorted(all_js_files),
        "all_forms": all_forms,
        "all_params": sorted(all_params),
        "blocked_by_robots": blocked_urls,
        "robots_txt": robots_info,
        "summary": {
            "pages_crawled": len(pages),
            "urls_found": len(all_urls),
            "js_files_found": len(all_js_files),
            "forms_found": len(all_forms),
            "params_found": len(all_params),
            "blocked_by_robots": len(blocked_urls),
            "scope": "subdomains" if allow_subdomains else "domain",
        },
    }


# ── Findings ──────────────────────────────────────────────────────────────────

_SENSITIVE_PATTERNS = [
    (r'/admin',                         "Admin panel",              "HIGH"),
    (r'/dashboard',                     "Dashboard page",           "MEDIUM"),
    (r'/login|/signin|/auth',           "Authentication page",      "INFO"),
    (r'/api/',                          "API endpoint",             "INFO"),
    (r'/graphql',                       "GraphQL endpoint",         "HIGH"),
    (r'/swagger|/openapi|/api-docs',    "API documentation exposed","MEDIUM"),
    (r'/\.git|/\.env|/\.htpasswd',      "Sensitive file exposed",   "CRITICAL"),
    (r'/backup|/dump|/export',          "Backup/export path",       "HIGH"),
    (r'/config|/settings',             "Config/settings page",     "MEDIUM"),
    (r'/register|/signup',             "Registration page",        "INFO"),
    (r'/upload|/file',                  "File upload page",         "HIGH"),
    (r'/debug|/test|/staging',          "Debug/test endpoint",      "MEDIUM"),
    (r'/phpinfo|/server-status|/server-info', "Server info leak",  "HIGH"),
    (r'/actuator',                      "Spring Actuator exposed",  "HIGH"),
    (r'/metrics|/healthz|/_ah/',        "Internal health endpoint", "MEDIUM"),
    (r'/wp-admin|/wp-login',            "WordPress admin",          "HIGH"),
    (r'/phpmyadmin',                    "phpMyAdmin exposed",       "CRITICAL"),
    (r'/jenkins|/hudson',               "Jenkins CI exposed",       "HIGH"),
    (r'/solr|/elastic|/_cat/',          "Search engine admin",      "HIGH"),
    (r'/console|/manager',              "Management console",       "HIGH"),
]


def pages_as_findings(crawl_results: dict) -> list[dict]:
    findings = []
    seen: set[str] = set()

    for url in crawl_results.get("all_urls", []):
        for pattern, label, severity in _SENSITIVE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                key = f"{label}::{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": f"Sensitive Path — {label}",
                        "severity": severity,
                        "url": url,
                        "description": f"{label} discovered at: {url}",
                        "recommendation": "Verify this path is intentionally public and properly access-controlled.",
                    })

    # Flag pages behind robots.txt as informational
    for url in crawl_results.get("blocked_by_robots", []):
        findings.append({
            "type": "Blocked by robots.txt",
            "severity": "INFO",
            "url": url,
            "description": f"Crawl blocked by robots.txt: {url}",
            "recommendation": "Review robots.txt to ensure sensitive paths aren't inadvertently hinted at.",
        })

    return findings


if __name__ == "__main__":
    pass
