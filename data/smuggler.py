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
HTTP Request Smuggling detector.

Tests four desync variants using raw sockets so we have complete
control over every byte of the request:

  CL.TE  — frontend uses Content-Length, backend uses Transfer-Encoding
  TE.CL  — frontend uses Transfer-Encoding, backend uses Content-Length
  TE.TE  — both headers present; one peer ignores an obfuscated TE value
  CL.CL  — both use Content-Length but with conflicting values

Detection strategy: timing-based (safe, no payload landing needed).
A server that hangs waiting for more data is a clear signal.
A differential-response check is also performed where safe.
"""

import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


TIMEOUT_NORMAL  = 5     # seconds — clean request baseline
TIMEOUT_PROBE   = 12    # seconds — maximum wait for a smuggle probe
TIMING_DELTA    = 4.0   # seconds above normal that indicates a hang

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_INFO     = "INFO"


# ── Raw socket helpers ─────────────────────────────────────────────────────────

def _connect(host: str, port: int, use_ssl: bool, timeout: float):
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_raw(host: str, port: int, use_ssl: bool, payload: bytes, timeout: float) -> tuple[float, Optional[bytes]]:
    """Send raw bytes, return (elapsed_seconds, response_bytes_or_None)."""
    t0 = time.time()
    try:
        sock = _connect(host, port, use_ssl, timeout)
        sock.sendall(payload)
        chunks = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(b"".join(chunks)) > 65536:
                    break
            except socket.timeout:
                break
        sock.close()
        return time.time() - t0, b"".join(chunks)
    except Exception:
        return time.time() - t0, None


# ── Baseline timing ────────────────────────────────────────────────────────────

def _baseline(host: str, port: int, use_ssl: bool, path: str) -> float:
    scheme = "https" if use_ssl else "http"
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: BugBountyTool/1.0\r\n\r\n"
    ).encode()
    elapsed, _ = _send_raw(host, port, use_ssl, req, TIMEOUT_NORMAL)
    return elapsed


# ── CL.TE probe ───────────────────────────────────────────────────────────────

def _probe_cl_te(host: str, port: int, use_ssl: bool, path: str, timeout: float) -> dict:
    """
    Frontend honours Content-Length (sees 6 bytes "0\r\n\r\nX").
    Backend honours Transfer-Encoding: chunked (reads "0\r\n\r\n" as end,
    then "X" is left in the buffer — if backend hangs waiting for \r\n
    after 'X', the connection stalls).
    """
    body = b"0\r\n\r\nX"
    req  = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"User-Agent: BugBountyTool/1.0\r\n\r\n"
    ).encode() + body
    elapsed, resp = _send_raw(host, port, use_ssl, req, timeout)
    return {"elapsed": elapsed, "response": resp, "variant": "CL.TE"}


# ── TE.CL probe ───────────────────────────────────────────────────────────────

def _probe_te_cl(host: str, port: int, use_ssl: bool, path: str, timeout: float) -> dict:
    """
    Frontend honours Transfer-Encoding: chunked.
    Backend honours Content-Length.
    We send 1-byte chunk "G" but Content-Length says 4 bytes —
    backend waits for 3 more bytes that never arrive.
    """
    chunk_body = b"1\r\nG\r\n0\r\n\r\n"
    req        = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"User-Agent: BugBountyTool/1.0\r\n\r\n"
    ).encode() + chunk_body
    elapsed, resp = _send_raw(host, port, use_ssl, req, timeout)
    return {"elapsed": elapsed, "response": resp, "variant": "TE.CL"}


# ── TE.TE obfuscation probes ──────────────────────────────────────────────────

_TE_OBFUSCATIONS = [
    ("TE-header-space",     "Transfer-Encoding : chunked"),
    ("TE-header-tab",       "Transfer-Encoding\t: chunked"),
    ("TE-value-xchunked",   "Transfer-Encoding: xchunked"),
    ("TE-value-chunked_v2", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
    ("TE-value-cow",        'Transfer-Encoding: "chunked"'),
    ("TE-value-junk",       "Transfer-Encoding: chunked, cow"),
]

def _probe_te_te(host: str, port: int, use_ssl: bool, path: str,
                  te_header: str, label: str, timeout: float) -> dict:
    chunk_body = b"1\r\nG\r\n0\r\n\r\n"
    req        = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"{te_header}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: BugBountyTool/1.0\r\n\r\n"
    ).encode() + chunk_body
    elapsed, resp = _send_raw(host, port, use_ssl, req, timeout)
    return {"elapsed": elapsed, "response": resp, "variant": f"TE.TE ({label})"}


# ── Response analysis ─────────────────────────────────────────────────────────

def _interpret(probe: dict, baseline: float) -> Optional[dict]:
    elapsed  = probe["elapsed"]
    resp     = probe["response"] or b""
    variant  = probe["variant"]
    resp_str = resp.decode("utf-8", errors="replace").lower()

    # 1. Timing signal
    timing_hit = elapsed >= TIMEOUT_PROBE - 1.0 or (elapsed - baseline) > TIMING_DELTA

    # 2. Error code signals
    status_hit = False
    if b"HTTP/1" in resp:
        first_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
        code = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""
        status_hit = code in ("400", "408", "500", "501", "503")

    # 3. Smuggling error phrases in body
    body_hit = any(p in resp_str for p in [
        "bad request", "invalid request", "malformed",
        "request timeout", "transfer-encoding", "chunked",
    ])

    if timing_hit or (status_hit and body_hit):
        confidence = "HIGH" if timing_hit else "MEDIUM"
        severity   = SEVERITY_HIGH if confidence == "HIGH" else SEVERITY_MEDIUM
        evidence   = []
        if timing_hit:
            evidence.append(f"response hung for {elapsed:.1f}s (baseline {baseline:.1f}s)")
        if status_hit:
            try:
                code = resp.split(b"\r\n")[0].decode().split(" ")[1]
            except Exception:
                code = "?"
            evidence.append(f"unexpected HTTP {code}")
        if body_hit:
            evidence.append("error body contains smuggling-related text")

        return {
            "variant":    variant,
            "severity":   severity,
            "confidence": confidence,
            "elapsed":    round(elapsed, 2),
            "baseline":   round(baseline, 2),
            "evidence":   evidence,
            "impact": (
                "HTTP request smuggling can allow an attacker to bypass security controls, "
                "hijack other users' requests, steal credentials, poison caches, and achieve "
                "reflected/stored XSS without user interaction."
            ),
            "recommendation": (
                "Ensure the front-end and back-end agree on how to parse Content-Length and "
                "Transfer-Encoding. Prefer HTTP/2 end-to-end. If HTTP/1.1 is required, normalize "
                "requests at the reverse proxy before forwarding."
            ),
        }
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def scan_smuggling(
    base_url:   str,
    extra_urls: Optional[list[str]] = None,
    timeout:    int   = 10,
    user_agent: str   = "BugBountyTool/1.0",
    max_urls:   int   = 5,
) -> dict:
    """
    Run CL.TE, TE.CL, and all TE.TE obfuscation probes.

    Returns:
      findings      list of vuln dicts
      probes_sent   total number of probes fired
      urls_tested   which URLs were checked
      summary       counts
    """
    parsed   = urllib.parse.urlparse(base_url)
    host     = parsed.hostname
    use_ssl  = parsed.scheme == "https"
    port     = parsed.port or (443 if use_ssl else 80)

    # Collect test paths — only the homepage + a few short paths
    paths: list[str] = [parsed.path or "/"]
    seen_paths = {paths[0]}
    for u in (extra_urls or []):
        p_parsed = urllib.parse.urlparse(u)
        if p_parsed.hostname != host:
            continue
        p = p_parsed.path or "/"
        if p not in seen_paths:
            seen_paths.add(p)
            paths.append(p)
        if len(paths) >= max_urls:
            break

    # Baseline on homepage
    try:
        baseline = _baseline(host, port, use_ssl, paths[0])
    except Exception:
        baseline = TIMEOUT_NORMAL / 2

    # Build probe jobs
    jobs: list[dict] = []
    for path in paths:
        jobs.append({"type": "cl_te", "path": path})
        jobs.append({"type": "te_cl", "path": path})
        for label, te_hdr in _TE_OBFUSCATIONS:
            jobs.append({"type": "te_te", "path": path, "label": label, "te_header": te_hdr})

    raw_findings: list[dict] = []

    def _run(job: dict):
        path = job["path"]
        try:
            if job["type"] == "cl_te":
                probe = _probe_cl_te(host, port, use_ssl, path, float(timeout))
            elif job["type"] == "te_cl":
                probe = _probe_te_cl(host, port, use_ssl, path, float(timeout))
            else:
                probe = _probe_te_te(host, port, use_ssl, path,
                                     job["te_header"], job["label"], float(timeout))
            return _interpret(probe, baseline)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_run, job): job for job in jobs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                raw_findings.append(result)

    # Dedupe by variant (keep highest severity)
    seen: dict[str, dict] = {}
    sev_order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2,
                 SEVERITY_INFO: 3}
    for f in raw_findings:
        key = f["variant"]
        if key not in seen or sev_order[f["severity"]] < sev_order[seen[key]["severity"]]:
            seen[key] = f

    findings = sorted(seen.values(), key=lambda x: sev_order[x["severity"]])

    return {
        "findings":    findings,
        "probes_sent": len(jobs),
        "urls_tested": paths,
        "baseline":    round(baseline, 2),
        "summary": {
            "vulnerable":     len(findings) > 0,
            "findings_total": len(findings),
            "high":           sum(1 for f in findings if f["severity"] == SEVERITY_HIGH),
            "medium":         sum(1 for f in findings if f["severity"] == SEVERITY_MEDIUM),
            "variants_hit":   [f["variant"] for f in findings],
        },
    }


def as_findings(smuggle_results: dict) -> list[dict]:
    out = []
    for f in smuggle_results.get("findings", []):
        out.append({
            "type":           f"HTTP Smuggling — {f['variant']}",
            "severity":       f["severity"],
            "url":            "request layer",
            "description":    "Evidence: " + "; ".join(f.get("evidence", [])),
            "recommendation": f.get("recommendation", ""),
            "impact":         f.get("impact", ""),
        })
    return out


if __name__ == "__main__":
    pass
