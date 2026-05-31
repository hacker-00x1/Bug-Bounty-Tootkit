"""
scope.py — Scope checker for the Bug Bounty Tool Kit.

Loads a program's scope definition (JSON or YAML) and filters findings so that
only in-scope assets make it into the final report.

Scope file format (JSON):
    {
        "program": "Example Bug Bounty Program",
        "in_scope": [
            "*.example.com",
            "api.example.com",
            "https://app.example.com/api"
        ],
        "out_of_scope": [
            "blog.example.com",
            "status.example.com",
            "*.s3.amazonaws.com"
        ]
    }

Patterns support:
  - Exact hostname match:      "api.example.com"
  - Wildcard subdomain:        "*.example.com"
  - URL prefix (host only):    "https://app.example.com"
  - IP address:                "192.168.1.1"

out_of_scope always takes precedence over in_scope.
"""

import json
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse


def load_scope(path: str) -> dict:
    """Load a scope file (JSON or YAML).

    Returns a dict with keys:
      - program (str)
      - in_scope  (list[str])
      - out_of_scope (list[str])

    Raises FileNotFoundError if the file does not exist.
    Raises ValueError for unrecognised file extensions.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Scope file not found: {path}\n"
            "Create one with --scope-file scope.json (see scope_example.json for the format)."
        )

    raw = p.read_text(encoding="utf-8")
    ext = p.suffix.lower()

    if ext in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            data: dict = yaml.safe_load(raw) or {}
        except ImportError:
            raise ImportError("PyYAML is required for YAML scope files: pip install pyyaml")
    elif ext in (".json", ""):
        data = json.loads(raw)
    else:
        raise ValueError(f"Unsupported scope file extension '{ext}'. Use .json or .yaml.")

    return {
        "program":      str(data.get("program", "")),
        "in_scope":     [s.strip() for s in data.get("in_scope",     []) if str(s).strip()],
        "out_of_scope": [s.strip() for s in data.get("out_of_scope", []) if str(s).strip()],
    }


def _hostname(url_or_pattern: str) -> str:
    """Extract bare hostname from a URL, pattern, or hostname string."""
    s = url_or_pattern.strip()
    if "://" in s:
        parsed = urlparse(s)
        return (parsed.hostname or "").lower()
    return s.split("/")[0].split(":")[0].lower()


def _matches(pattern: str, hostname: str) -> bool:
    """Return True if *hostname* matches *pattern* (supports *.foo.com)."""
    pat_host = _hostname(pattern)
    host     = hostname.lower()
    return fnmatch(host, pat_host)


def is_in_scope(url: str, scope: dict) -> tuple[bool, str]:
    """Check whether *url* is in scope according to the loaded scope definition.

    Returns (in_scope: bool, reason: str).
    An empty / missing scope definition treats everything as in scope.
    """
    in_scope_pats     = scope.get("in_scope",     [])
    out_of_scope_pats = scope.get("out_of_scope", [])

    if not in_scope_pats and not out_of_scope_pats:
        return (True, "No scope restrictions defined — all assets in scope.")

    try:
        raw = url if "://" in url else f"https://{url}"
        hostname = urlparse(raw).hostname or url
    except Exception:
        hostname = url

    for pat in out_of_scope_pats:
        if _matches(pat, hostname):
            return (False, f"Out-of-scope pattern: {pat}")

    if in_scope_pats:
        for pat in in_scope_pats:
            if _matches(pat, hostname):
                return (True, f"In-scope pattern: {pat}")
        return (False, f"No in-scope pattern matches host '{hostname}'")

    return (True, "No in-scope list defined — not excluded by out-of-scope.")


def filter_findings(findings: list, scope: dict) -> tuple[list, list]:
    """Split *findings* into (in_scope, excluded).

    Each excluded finding gets an ``out_of_scope_reason`` key added.
    The original list objects are mutated in-place so callers' references stay valid.
    """
    keep: list    = []
    excluded: list = []

    for f in findings:
        url = f.get("url") or f.get("asset") or ""
        ok, reason = is_in_scope(url, scope)
        if ok:
            keep.append(f)
        else:
            f["out_of_scope_reason"] = reason
            excluded.append(f)

    return keep, excluded


def filter_results(results: dict, scope: dict) -> list:
    """Filter all finding lists inside a scan *results* dict in-place.

    Returns the combined list of excluded findings so the caller can log them.
    Each finding source list is cleared and repopulated with only in-scope items.
    """
    all_excluded: list = []

    def _apply(lst: list) -> None:
        keep, excl = filter_findings(list(lst), scope)
        lst.clear()
        lst.extend(keep)
        all_excluded.extend(excl)

    for key in ["header_issues", "cors_issues", "open_redirect_issues", "xss_issues",
                "sqli_issues", "lfi_issues", "sensitive_files", "http_method_issues"]:
        _apply(results.get("vulns", {}).get(key, []))

    _apply(results.get("takeover",   {}).get("findings",           []))
    _apply(results.get("xss",        {}).get("findings",           []))
    _apply(results.get("js",         {}).get("converted_findings", []))
    _apply(results.get("crawl",      {}).get("path_findings",      []))
    _apply(results.get("cors_deep",  {}).get("converted_findings", []))
    _apply(results.get("smuggle",    {}).get("converted_findings", []))
    _apply(results.get("redirect",   {}).get("converted_findings", []))
    _apply(results.get("owasp",      {}).get("summary", {}).get("all_findings", []))

    for adv_key in ["sqli", "auth", "pathtraversal", "cmdinject", "bizlogic",
                    "infodisclosure", "accesscontrol", "fileupload", "raceconditions",
                    "ssrf", "xxe", "nosqli", "apitest", "webcache"]:
        _apply(results.get(adv_key, {}).get("findings", []))

    return all_excluded
