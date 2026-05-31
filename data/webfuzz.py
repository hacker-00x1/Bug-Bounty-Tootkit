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

import re
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


TECH_SIGNATURES = {
    "WordPress": [
        ("header", "x-powered-by", "wordpress"),
        ("header", "link", "wp-json"),
        ("body", None, r'wp-content/'),
        ("body", None, r'wp-includes/'),
    ],
    "Drupal": [
        ("header", "x-generator", "drupal"),
        ("body", None, r'Drupal\.settings'),
        ("body", None, r'/sites/default/files/'),
    ],
    "Joomla": [
        ("body", None, r'/media/jui/'),
        ("body", None, r'Joomla!'),
    ],
    "Laravel": [
        ("header", "set-cookie", "laravel_session"),
        ("body", None, r'Laravel'),
    ],
    "Django": [
        ("header", "x-frame-options", "sameorigin"),
        ("body", None, r'csrfmiddlewaretoken'),
    ],
    "Rails": [
        ("header", "x-powered-by", "phusion passenger"),
        ("header", "set-cookie", "_session_id"),
    ],
    "React": [
        ("body", None, r'__reactFiber|_reactRootContainer'),
    ],
    "Angular": [
        ("body", None, r'ng-version='),
    ],
    "Vue.js": [
        ("body", None, r'__vue__|v-app'),
    ],
    "jQuery": [
        ("body", None, r'jquery[.-](\d+\.\d+)'),
    ],
    "Bootstrap": [
        ("body", None, r'bootstrap\.min\.css|bootstrap\.min\.js'),
    ],
    "nginx": [
        ("header", "server", "nginx"),
    ],
    "Apache": [
        ("header", "server", "apache"),
    ],
    "IIS": [
        ("header", "server", "iis"),
        ("header", "x-powered-by", "asp.net"),
    ],
    "PHP": [
        ("header", "x-powered-by", "php"),
        ("header", "set-cookie", "phpsessid"),
    ],
    "Cloudflare": [
        ("header", "server", "cloudflare"),
        ("header", "cf-ray", None),
    ],
    "AWS": [
        ("header", "x-amz-request-id", None),
        ("header", "x-amz-cf-id", None),
    ],
    "Varnish": [
        ("header", "via", "varnish"),
        ("header", "x-varnish", None),
    ],
}


def fetch_url(url: str, timeout: int = 8, user_agent: str = "BugBountyTool/1.0",
              follow_redirects: bool = True) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        handler = urllib.request.HTTPRedirectHandler() if follow_redirects else urllib.request.BaseHandler()
        opener = urllib.request.build_opener(handler)

        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(50000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": resp.url,
                "status": resp.status,
                "headers": headers,
                "body": body,
                "content_length": len(body),
            }
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        try:
            body = e.read(5000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "url": url,
            "status": e.code,
            "headers": headers,
            "body": body,
            "content_length": len(body),
        }
    except Exception:
        return None


def detect_technologies(response: dict) -> list[str]:
    detected = []
    headers = response.get("headers", {})
    body = response.get("body", "")

    for tech, signatures in TECH_SIGNATURES.items():
        for sig_type, header_name, pattern in signatures:
            matched = False
            if sig_type == "header":
                if header_name in headers:
                    val = headers[header_name].lower()
                    if pattern is None or pattern.lower() in val:
                        matched = True
            elif sig_type == "body" and pattern:
                if re.search(pattern, body, re.IGNORECASE):
                    matched = True
            if matched:
                detected.append(tech)
                break

    return list(set(detected))


def fuzz_directories(base_url: str, wordlist: list[str], threads: int = 20,
                     timeout: int = 5, user_agent: str = "BugBountyTool/1.0") -> list[dict]:
    found = []
    base_url = base_url.rstrip("/")

    interesting_codes = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    def check(path: str) -> Optional[dict]:
        url = f"{base_url}/{path}"
        result = fetch_url(url, timeout=timeout, user_agent=user_agent, follow_redirects=False)
        if result and result["status"] in interesting_codes:
            return {
                "url": url,
                "status": result["status"],
                "size": result["content_length"],
                "interesting": result["status"] not in {404, 400},
            }
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, path): path for path in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["status"])


def extract_links(response: dict, base_domain: str) -> dict:
    body = response.get("body", "")
    all_links = re.findall(r'href=["\']([^"\']+)["\']|src=["\']([^"\']+)["\']', body)
    links = [l[0] or l[1] for l in all_links if l[0] or l[1]]

    internal = []
    external = []
    for link in links:
        if not link or link.startswith("#") or link.startswith("javascript:"):
            continue
        if base_domain in link or link.startswith("/"):
            internal.append(link)
        elif link.startswith("http"):
            external.append(link)

    return {
        "internal": sorted(set(internal)),
        "external": sorted(set(external)),
    }


if __name__ == "__main__":
    pass
