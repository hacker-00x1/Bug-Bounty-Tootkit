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

import socket
import urllib.request
import urllib.error
import re
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "body_patterns": ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokudns.com"],
        "body_patterns": ["No such app", "herokucdn.com/error-pages/no-such-app.html", "There's nothing here, yet."],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
        "body_patterns": ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"],
        "status_codes": [403, 404],
        "severity": "HIGH",
    },
    {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "body_patterns": ["Bad request.", "ERROR: The request could not be satisfied"],
        "status_codes": [403],
        "severity": "MEDIUM",
    },
    {
        "service": "Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                           "blob.core.windows.net", "azure-api.net"],
        "body_patterns": ["is not deployed", "404 Web Site not found.", "ErrorCode=\"BlobNotFound\"",
                          "StorageErrorCode=BlobNotFound"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "body_patterns": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "body_patterns": ["Sorry, this shop is currently unavailable.", "Only one step left!"],
        "status_codes": [404],
        "severity": "MEDIUM",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "body_patterns": ["Whatever you were looking for doesn't currently exist at this address.",
                          "There's nothing here."],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "body_patterns": ["Help Center Closed", "This help center no longer exists"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com"],
        "body_patterns": ["Not Found - Request ID", "netlify.com/products/"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "vercel-dns.com", "now.sh"],
        "body_patterns": ["The deployment you're looking for doesn't exist"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "body_patterns": ["project not found", "is not a Surge project"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "body_patterns": ["The thing you were looking for is no longer here", "404"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io", "pantheon.io"],
        "body_patterns": ["404 error unknown site", "The gods are wise"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Webflow",
        "cname_patterns": ["webflow.io"],
        "body_patterns": ["The page you are looking for doesn't exist or has been moved", "Page Not Found"],
        "status_codes": [404],
        "severity": "MEDIUM",
    },
    {
        "service": "Squarespace",
        "cname_patterns": ["squarespace.com"],
        "body_patterns": ["No Such Account", "this domain hasn't been set up yet"],
        "status_codes": [404],
        "severity": "MEDIUM",
    },
    {
        "service": "WPEngine",
        "cname_patterns": ["wpengine.com"],
        "body_patterns": ["The site you were looking for couldn't be found"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.com", "hubspotpagebuilder.com"],
        "body_patterns": ["Domain not found", "does not exist in our system"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Intercom",
        "cname_patterns": ["intercom.io", "custom.intercom.help"],
        "body_patterns": ["This page is reserved for artistic works", "Uh oh. That page doesn't exist."],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev", "fly.io"],
        "body_patterns": ["404 Not Found"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Render",
        "cname_patterns": ["onrender.com"],
        "body_patterns": ["Service not found", "404"],
        "status_codes": [404],
        "severity": "HIGH",
    },
    {
        "service": "Cargo",
        "cname_patterns": ["cargocollective.com"],
        "body_patterns": ["404 Not Found", "If you're moving your domain away from Cargo"],
        "status_codes": [404],
        "severity": "MEDIUM",
    },
    {
        "service": "Sendgrid",
        "cname_patterns": ["sendgrid.net"],
        "body_patterns": ["404"],
        "status_codes": [404],
        "severity": "MEDIUM",
    },
]


def get_cname_chain(hostname: str) -> list[str]:
    chain = []
    current = hostname
    seen = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for _ in range(10):
        if current in seen:
            break
        seen.add(current)
        try:
            answers = resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            break
        except Exception:
            break
    return chain


def resolve_nxdomain(hostname: str) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        resolver.resolve(hostname, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def fetch_body(url: str, timeout: int = 8) -> Optional[dict]:
    headers = {"User-Agent": "BugBountyTool/1.0"}
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{url}", headers=headers)
            opener = urllib.request.build_opener(urllib.request.BaseHandler())
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(8000).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8000).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return {"status": e.code, "body": body}
        except Exception:
            continue
    return None


def _match_fingerprint(cname_chain: list[str], response: Optional[dict], fp: dict) -> bool:
    cname_str = " ".join(cname_chain).lower()
    cname_hit = any(pat.lower() in cname_str for pat in fp["cname_patterns"])
    if not cname_hit:
        return False

    if response is None:
        return False

    status_hit = response["status"] in fp["status_codes"]
    body_hit = any(pat.lower() in response["body"].lower() for pat in fp["body_patterns"])

    return status_hit and body_hit


def check_subdomain_takeover(subdomain: str, timeout: int = 8) -> Optional[dict]:
    cname_chain = get_cname_chain(subdomain)

    if not cname_chain:
        return None

    final_cname = cname_chain[-1]
    is_nxdomain = resolve_nxdomain(final_cname)

    response = fetch_body(subdomain, timeout)

    for fp in FINGERPRINTS:
        if _match_fingerprint(cname_chain, response, fp):
            return {
                "type": "Subdomain Takeover",
                "severity": fp["severity"],
                "subdomain": subdomain,
                "service": fp["service"],
                "cname_chain": " → ".join(cname_chain),
                "nxdomain": is_nxdomain,
                "status_code": response["status"] if response else None,
                "description": (
                    f"Potential subdomain takeover via {fp['service']} — "
                    f"{subdomain} CNAME points to unclaimed {fp['service']} resource"
                ),
                "recommendation": (
                    f"Remove the CNAME record for {subdomain} or claim the "
                    f"{fp['service']} resource immediately"
                ),
            }

    if is_nxdomain and cname_chain:
        cname_str = " ".join(cname_chain).lower()
        for fp in FINGERPRINTS:
            if any(pat.lower() in cname_str for pat in fp["cname_patterns"]):
                return {
                    "type": "Subdomain Takeover (NXDOMAIN)",
                    "severity": fp["severity"],
                    "subdomain": subdomain,
                    "service": fp["service"],
                    "cname_chain": " → ".join(cname_chain),
                    "nxdomain": True,
                    "status_code": None,
                    "description": (
                        f"Potential subdomain takeover — {subdomain} CNAME resolves to NXDOMAIN "
                        f"on {fp['service']}"
                    ),
                    "recommendation": (
                        f"Remove the dangling CNAME record for {subdomain} immediately"
                    ),
                }

    return None


def scan_subdomains_for_takeover(subdomains: list[str | dict], threads: int = 15,
                                  timeout: int = 8) -> list[dict]:
    results = []

    hostnames = []
    for s in subdomains:
        if isinstance(s, dict):
            hostnames.append(s.get("subdomain", ""))
        else:
            hostnames.append(s)
    hostnames = [h for h in hostnames if h]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain_takeover, host, timeout): host
                   for host in hostnames}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x.get("severity", "LOW"), 99))
    return results


if __name__ == "__main__":
    pass
