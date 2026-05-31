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

import json
import os
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}
SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fffbeb",
    "LOW": "#eff6ff",
    "INFO": "#f9fafb",
}


def save_json(results: dict, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    return output_path


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;">{severity}</span>'


def _count_by_severity(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def _all_findings(results: dict) -> list[dict]:
    findings = []
    for section in ["header_issues", "cors_issues", "open_redirect_issues",
                     "xss_issues", "sqli_issues", "lfi_issues", "sensitive_files",
                     "http_method_issues"]:
        findings.extend(results.get("vulns", {}).get(section, []))
    findings.extend(results.get("takeover", {}).get("findings", []))
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))
    return findings


def save_html(results: dict, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    target = results.get("target", "Unknown")
    scan_time = results.get("scan_time", "")
    ip = results.get("ip", "N/A")
    findings = _all_findings(results)
    counts = _count_by_severity(findings)
    open_ports = results.get("ports", {}).get("open_ports", [])
    subdomains = results.get("recon", {}).get("subdomains", [])
    dns = results.get("recon", {}).get("dns", {})
    techs = results.get("web", {}).get("technologies", [])
    dirs = results.get("web", {}).get("directories", [])
    takeover_findings = results.get("takeover", {}).get("findings", [])
    xss_findings = results.get("xss", {}).get("findings", [])
    crawl_data = results.get("crawl", {})
    crawl_summary = crawl_data.get("summary", {})
    crawl_pages_list = crawl_data.get("pages", [])
    crawl_all_urls = crawl_data.get("all_urls", [])
    crawl_params = crawl_data.get("all_params", [])
    crawl_forms = crawl_data.get("all_forms", [])
    crawl_path_findings = crawl_data.get("path_findings", [])
    cors_data = results.get("cors_deep", {})
    cors_findings = cors_data.get("findings", [])
    cors_summary = cors_data.get("summary", {})
    cors_preflight = cors_data.get("preflight", {})
    redir_data     = results.get("redirect", {})
    redir_findings = redir_data.get("findings", [])
    redir_summary  = redir_data.get("summary", {})
    smuggle_data     = results.get("smuggle", {})
    smuggle_findings = smuggle_data.get("findings", [])
    smuggle_summary  = smuggle_data.get("summary", {})
    waf_data = results.get("waf", {})
    waf_detected = waf_data.get("detected", [])
    waf_primary = waf_data.get("primary_waf", None)
    waf_rl = waf_data.get("rate_limit", {})
    waf_headers = waf_data.get("interesting_headers", {})
    js_data = results.get("js", {})
    js_secrets = js_data.get("all_secrets", [])
    js_sinks = js_data.get("all_sinks", [])
    js_endpoints = js_data.get("all_endpoints", [])
    js_source_maps = js_data.get("all_source_maps", [])
    js_files = js_data.get("files_scanned", [])
    js_summary = js_data.get("summary", {})

    risk_score = (
        counts["CRITICAL"] * 40 +
        counts["HIGH"] * 20 +
        counts["MEDIUM"] * 5 +
        counts["LOW"] * 1
    )
    if risk_score >= 80:
        risk_label, risk_color = "CRITICAL", "#dc2626"
    elif risk_score >= 40:
        risk_label, risk_color = "HIGH", "#ea580c"
    elif risk_score >= 10:
        risk_label, risk_color = "MEDIUM", "#d97706"
    elif risk_score > 0:
        risk_label, risk_color = "LOW", "#2563eb"
    else:
        risk_label, risk_color = "CLEAN", "#16a34a"

    findings_html = ""
    for fi, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        bg = SEVERITY_BG.get(sev, "#f9fafb")
        border = SEVERITY_COLORS.get(sev, "#6b7280")
        cvss_score  = f.get("cvss_score") or (f.get("cvss","") or "").split(" ")[0]
        cvss_vector = f.get("cvss_vector") or (f.get("cvss","") or "")
        steps       = f.get("steps_to_reproduce","")
        impact      = f.get("impact","")
        rec         = f.get("recommendation","")
        url         = f.get("url","")
        payload     = f.get("payload") or f.get("payload_type") or ""
        param       = f.get("param","")
        ref_links   = f.get("references","")

        steps_html = ""
        if steps:
            lines = steps.strip().split("\n")
            items = "".join(f"<li style='margin:3px 0;font-family:monospace;font-size:12px;'>{l.strip()}</li>" for l in lines if l.strip())
            steps_html = f"<div style='margin:10px 0 6px;'><strong style='color:#374151;font-size:13px;'>🔬 Steps to Reproduce</strong><ol style='margin:6px 0 0 18px;padding:0;color:#374151;'>{items}</ol></div>"

        cvss_html = ""
        if cvss_score:
            score_val = cvss_score.split(" ")[0]
            try:
                score_f = float(score_val)
                sc = "#dc2626" if score_f >= 9.0 else "#ea580c" if score_f >= 7.0 else "#d97706" if score_f >= 4.0 else "#2563eb"
            except Exception:
                sc = border
            cvss_html = (
                f"<span style='background:{sc};color:white;padding:2px 10px;border-radius:12px;"
                f"font-size:11px;font-weight:700;margin-left:8px;'>CVSS {cvss_score}</span>"
            )
            if cvss_vector and "CVSS:" in cvss_vector:
                cvss_html += f"<code style='margin-left:8px;font-size:10px;color:#6b7280;'>{cvss_vector.split(' — ')[-1] if ' — ' in cvss_vector else cvss_vector}</code>"

        url_html = (
            f"<div style='margin:6px 0;'>"
            f"<span style='font-size:11px;color:#6b7280;font-weight:600;'>🔗 URL</span>&nbsp;"
            f"<code style='font-size:12px;word-break:break-all;color:#1d4ed8;background:#eff6ff;padding:2px 6px;border-radius:4px;'>{url}</code>"
            f"</div>"
        ) if url else ""

        payload_html = (
            f"<div style='margin:6px 0;'>"
            f"<span style='font-size:11px;color:#6b7280;font-weight:600;'>💉 Payload</span>&nbsp;"
            f"<code style='font-size:12px;color:#7c3aed;background:#f5f3ff;padding:2px 6px;border-radius:4px;word-break:break-all;'>{payload}</code>"
            f"</div>"
        ) if payload else ""

        param_html = (
            f"<span style='font-size:11px;background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:8px;margin-left:8px;'>param: {param}</span>"
        ) if param else ""

        impact_html = (
            f"<div style='margin:8px 0 4px;background:#fff7ed;border-left:3px solid #ea580c;padding:8px 12px;border-radius:0 6px 6px 0;'>"
            f"<span style='font-size:11px;font-weight:700;color:#ea580c;'>⚡ IMPACT</span>"
            f"<p style='margin:4px 0 0;font-size:13px;color:#374151;'>{impact}</p>"
            f"</div>"
        ) if impact else ""

        rec_html = (
            f"<div style='margin:8px 0 4px;background:#f0fdf4;border-left:3px solid #16a34a;padding:8px 12px;border-radius:0 6px 6px 0;'>"
            f"<span style='font-size:11px;font-weight:700;color:#16a34a;'>🛡 REMEDIATION</span>"
            f"<p style='margin:4px 0 0;font-size:13px;color:#374151;'>{rec}</p>"
            f"</div>"
        ) if rec else ""

        findings_html += f"""
        <div id="finding-{fi}" style="border:1px solid {border};border-left:5px solid {border};background:{bg};padding:18px 20px;margin-bottom:16px;border-radius:0 10px 10px 0;box-shadow:0 1px 4px rgba(0,0,0,.07);">
          <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:10px;">
            <span style="font-size:13px;font-weight:700;color:#111827;">[F-{fi:02d}] {f.get('type','Finding')}</span>
            {_severity_badge(sev)}{param_html}{cvss_html}
          </div>
          <p style="margin:0 0 8px;color:#374151;font-size:14px;">{f.get('description','')}</p>
          {url_html}{payload_html}{steps_html}{impact_html}{rec_html}
        </div>"""

    ports_html = ""
    for p in open_ports:
        service_vulns = p.get("service_vulns", [])
        vuln_html = "".join(f"<li style='color:#dc2626;'>{v}</li>" for v in service_vulns)
        ports_html += f"""
        <tr>
          <td style="padding:8px 12px;font-weight:600;">{p['port']}</td>
          <td style="padding:8px 12px;">{p.get('service','')}</td>
          <td style="padding:8px 12px;color:#16a34a;font-weight:600;">{p['state'].upper()}</td>
          <td style="padding:8px 12px;font-size:12px;color:#6b7280;font-family:monospace;">{(p.get('banner') or '')[:80]}</td>
          <td style="padding:8px 12px;"><ul style="margin:0;padding-left:16px;">{vuln_html}</ul></td>
        </tr>"""

    subdomains_html = "".join(
        f"<tr><td style='padding:6px 12px;'>{s.get('subdomain', s) if isinstance(s, dict) else s}</td>"
        f"<td style='padding:6px 12px;color:#6b7280;'>{s.get('ip','') if isinstance(s, dict) else ''}</td></tr>"
        for s in (subdomains[:50] if subdomains else [])
    )

    dns_html = ""
    for rtype, records in dns.items():
        if records:
            dns_html += f"<tr><td style='padding:6px 12px;font-weight:600;'>{rtype}</td><td style='padding:6px 12px;font-family:monospace;font-size:13px;'>{', '.join(records)}</td></tr>"

    takeover_rows = ""
    for f in takeover_findings:
        sev = f.get("severity", "HIGH")
        sev_color = SEVERITY_COLORS.get(sev, "#ea580c")
        takeover_rows += (
            f"<tr><td style='padding:8px 12px;font-weight:600;'>{f.get('subdomain','')}</td>"
            f"<td style='padding:8px 12px;'>{f.get('service','')}</td>"
            f"<td style='padding:8px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{sev}</span></td>"
            f"<td style='padding:8px 12px;font-size:12px;font-family:monospace;color:#6b7280;'>{f.get('cname_chain','')}</td>"
            f"<td style='padding:8px 12px;font-size:13px;color:#059669;'>{f.get('recommendation','')}</td></tr>"
        )
    xss_rows = ""
    for f in xss_findings:
        sev = f.get("severity", "HIGH")
        sev_color = SEVERITY_COLORS.get(sev, "#ea580c")
        confirmed = f.get("confirmed_xss", False)
        confirmed_html = "<span style='color:#16a34a;font-weight:700;'>YES</span>" if confirmed else "<span style='color:#6b7280;'>—</span>"
        working_payloads = [p["payload"] for p in f.get("payloads", []) if p.get("reflected_unencoded")]
        payload_list = "".join(
            f"<code style='display:block;background:#1f2937;color:#f9fafb;padding:4px 8px;border-radius:4px;font-size:11px;margin:2px 0;word-break:break-all;'>{p}</code>"
            for p in working_payloads[:4]
        )
        waf_list = "".join(
            f"<code style='display:block;background:#7c3aed;color:#f9fafb;padding:4px 8px;border-radius:4px;font-size:11px;margin:2px 0;word-break:break-all;'>{p}</code>"
            for p in f.get("waf_bypass_payloads", [])[:3]
        )
        xss_rows += (
            f"<tr>"
            f"<td style='padding:10px 12px;font-family:monospace;font-weight:600;'>?{f.get('param','')}=</td>"
            f"<td style='padding:10px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{sev}</span></td>"
            f"<td style='padding:10px 12px;'>{f.get('context_label','')}</td>"
            f"<td style='padding:10px 12px;'>{confirmed_html}</td>"
            f"<td style='padding:10px 12px;'>{payload_list}</td>"
            f"<td style='padding:10px 12px;'>{waf_list}</td>"
            f"<td style='padding:10px 12px;font-size:12px;color:#059669;'>{f.get('recommendation','')}</td>"
            f"</tr>"
        )

    # ── Smuggling card ────────────────────────────────────────────────────────
    smuggle_card = ""
    if smuggle_summary.get("probes_sent", 0) or smuggle_findings:
        vuln_color = "#dc2626" if smuggle_findings else "#16a34a"
        sm_title   = (
            f"⚠ {len(smuggle_findings)} desync variant(s) detected"
            if smuggle_findings else
            f"✅ No request smuggling detected"
        )
        sm_rows = ""
        for f in smuggle_findings:
            sev_color = {"CRITICAL": "#7c3aed", "HIGH": "#dc2626",
                         "MEDIUM": "#d97706", "LOW": "#2563eb"}.get(f.get("severity","HIGH"), "#dc2626")
            evidence  = "<br>".join(f.get("evidence", []))
            sm_rows += (
                f"<tr>"
                f"<td style='padding:8px 12px;'><span style='background:{sev_color};color:white;"
                f"padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>"
                f"{f.get('severity','')}</span></td>"
                f"<td style='padding:8px 12px;font-weight:700;font-family:monospace;'>{f.get('variant','')}</td>"
                f"<td style='padding:8px 12px;font-size:12px;color:#6b7280;'>{evidence}</td>"
                f"<td style='padding:8px 12px;font-size:11px;color:#7c3aed;'>{f.get('confidence','')}</td>"
                f"</tr>"
            )
        probe_info = (
            f"Tested {smuggle_summary.get('probes_sent',0)} probes across "
            f"{len(smuggle_data.get('urls_tested',[]))} URL(s)  |  "
            f"baseline {smuggle_data.get('baseline',0):.2f}s"
        )
        impact_html = ""
        if smuggle_findings:
            impact_html = (
                f"<div style='margin-top:14px;background:#fef2f2;border:1px solid #fecaca;"
                f"border-radius:8px;padding:12px 16px;font-size:13px;color:#991b1b;'>"
                f"<strong>⚠ Impact:</strong> {smuggle_findings[0].get('impact','')}"
                f"</div>"
                f"<div style='margin-top:10px;background:#f0fdf4;border:1px solid #bbf7d0;"
                f"border-radius:8px;padding:12px 16px;font-size:13px;color:#166534;'>"
                f"<strong>Fix:</strong> {smuggle_findings[0].get('recommendation','')}"
                f"</div>"
            )
        smuggle_card = (
            f"<div class='card' style='border:2px solid {vuln_color};'>"
            f"<h2 style='color:{vuln_color};'>💉 HTTP Request Smuggling — {sm_title}</h2>"
            f"<p style='color:#6b7280;font-size:12px;margin-bottom:12px;'>{probe_info}</p>"
            + (
                f"<table><thead><tr><th>Severity</th><th>Variant</th>"
                f"<th>Evidence</th><th>Confidence</th></tr></thead>"
                f"<tbody>{sm_rows}</tbody></table>"
                if smuggle_findings else
                f"<p style='color:#16a34a;font-size:13px;'>CL.TE, TE.CL, and TE.TE obfuscation "
                f"probes all returned within normal timing — no desync observed.</p>"
            )
            + impact_html
            + f"</div>"
        )

    # ── WAF card ──────────────────────────────────────────────────────────────
    waf_card = ""
    if waf_data:
        waf_color   = "#d97706" if waf_primary else "#16a34a"
        waf_title_label = f"⚠ {waf_primary} detected" if waf_primary else "✅ No WAF detected"
        rl_triggered = waf_rl.get("triggered", False)
        rl_color     = "#dc2626" if rl_triggered else "#16a34a"

        # Matched WAF rows
        waf_rows_html = ""
        for d in waf_detected:
            bar_w = d["confidence"]
            waf_rows_html += (
                f"<tr>"
                f"<td style='padding:8px 12px;font-weight:600;'>{d['name']}</td>"
                f"<td style='padding:8px 12px;'>"
                f"<div style='background:#e5e7eb;border-radius:6px;height:12px;width:180px;display:inline-block;vertical-align:middle;'>"
                f"<div style='background:#d97706;height:12px;border-radius:6px;width:{bar_w}%;'></div></div> "
                f"<span style='font-size:12px;color:#6b7280;'>{d['confidence']}%</span>"
                f"</td>"
                f"<td style='padding:8px 12px;font-size:12px;color:#6b7280;'>{d['signals_matched']}/{d['total_signals']} signals</td>"
                f"</tr>"
            )

        # Interesting headers table
        hdr_rows_html = "".join(
            f"<tr><td style='padding:4px 12px;font-family:monospace;font-size:12px;color:#2563eb;'>{k}</td>"
            f"<td style='padding:4px 12px;font-family:monospace;font-size:12px;word-break:break-all;'>{v[:120]}</td></tr>"
            for k, v in list(waf_headers.items())[:20]
        )

        # Rate-limit block
        rl_html = (
            f"<h3 style='font-size:14px;margin:16px 0 8px;color:{rl_color};'>⚡ Rate-Limit Probe</h3>"
            f"<table style='font-size:13px;'><tbody>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Triggered</td>"
            f"<td style='padding:4px 12px;font-weight:700;color:{rl_color};'>{'YES' if rl_triggered else 'no'}</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Burst size</td>"
            f"<td style='padding:4px 12px;'>{waf_rl.get('burst_size', 0)} requests</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Blocked</td>"
            f"<td style='padding:4px 12px;'>{waf_rl.get('blocked_count', 0)} ({waf_rl.get('pct_blocked', 0)}%)</td></tr>"
            + (f"<tr><td style='padding:4px 12px;font-weight:600;'>First block at</td>"
               f"<td style='padding:4px 12px;'>request #{waf_rl.get('first_block_at', '—')}</td></tr>"
               if rl_triggered else "")
            + f"</tbody></table>"
        )

        tuning_html = ""
        rec_t = waf_data.get("recommended_threads")
        rec_d = waf_data.get("recommended_delay_ms")
        notes = waf_data.get("notes", "")
        if rec_t or rec_d:
            tuning_html = (
                f"<div style='margin-top:14px;background:#fef9c3;border:1px solid #fde047;border-radius:8px;padding:12px 16px;font-size:13px;'>"
                f"<strong>🎛 Auto-tuning recommendation:</strong> threads={rec_t}, crawl-delay={rec_d} ms<br>"
                f"<span style='color:#6b7280;'>{notes}</span>"
                f"</div>"
            )

        waf_card = (
            f"<div class='card' style='border:2px solid {waf_color};'>"
            f"<h2 style='color:{waf_color};'>🛡 WAF &amp; Rate-Limit Detection — {waf_title_label}</h2>"
            + (
                f"<table><thead><tr><th>WAF / CDN</th><th>Confidence</th><th>Signals</th></tr></thead>"
                f"<tbody>{waf_rows_html}</tbody></table>"
                if waf_detected else
                f"<p style='color:#16a34a;font-size:13px;'>No signatures from 20 known WAFs matched. "
                f"The target may be unprotected or using an unrecognised solution.</p>"
            )
            + rl_html
            + (
                f"<h3 style='font-size:14px;margin:16px 0 8px;color:#374151;'>🔎 Interesting Response Headers</h3>"
                f"<table style='font-size:12px;'><thead><tr><th>Header</th><th>Value</th></tr></thead>"
                f"<tbody>{hdr_rows_html}</tbody></table>"
                if hdr_rows_html else ""
            )
            + tuning_html
            + f"</div>"
        )

    # ── CORS card ─────────────────────────────────────────────────────────────
    cors_rows = ""
    for f in cors_findings:
        sev_color = SEVERITY_COLORS.get(f.get("severity", "HIGH"), "#ea580c")
        creds_html = (
            "<span style='background:#dc2626;color:white;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:700;'>YES</span>"
            if f.get("with_credentials") else "<span style='color:#9ca3af;'>—</span>"
        )
        vary_html = (
            "<span style='color:#dc2626;font-size:11px;'>missing</span>"
            if f.get("vary_missing") else "<span style='color:#16a34a;font-size:11px;'>✓</span>"
        )
        short_url = f.get("url", "")
        if len(short_url) > 60:
            short_url = short_url[:57] + "…"
        cors_rows += (
            f"<tr>"
            f"<td style='padding:8px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{f.get('severity','')}</span></td>"
            f"<td style='padding:8px 12px;font-weight:600;'>{f.get('label','')}</td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:11px;color:#059669;'>{f.get('origin_sent','')}</td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:11px;color:#dc2626;font-weight:600;'>{f.get('acao','')}</td>"
            f"<td style='padding:8px 12px;text-align:center;'>{creds_html}</td>"
            f"<td style='padding:8px 12px;text-align:center;'>{vary_html}</td>"
            f"<td style='padding:8px 12px;font-size:11px;color:#6b7280;font-family:monospace;word-break:break-all;'>{short_url}</td>"
            f"</tr>"
        )

    preflight_html = ""
    if cors_preflight:
        pf_acao = cors_preflight.get("acao", "—")
        pf_acac = cors_preflight.get("acac", "—")
        pf_acam = cors_preflight.get("acam", "—")
        pf_acah = cors_preflight.get("acah", "—")
        pf_acma = cors_preflight.get("acma", "—")
        preflight_html = (
            f"<h3 style='font-size:14px;margin:16px 0 8px;color:#6b7280;'>OPTIONS Preflight (Origin: https://evil.com)</h3>"
            f"<table style='font-size:12px;'><tbody>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>ACAO</td><td style='padding:4px 12px;font-family:monospace;'>{pf_acao}</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Allow-Credentials</td><td style='padding:4px 12px;font-family:monospace;'>{pf_acac}</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Allow-Methods</td><td style='padding:4px 12px;font-family:monospace;'>{pf_acam}</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Allow-Headers</td><td style='padding:4px 12px;font-family:monospace;'>{pf_acah}</td></tr>"
            f"<tr><td style='padding:4px 12px;font-weight:600;'>Max-Age</td><td style='padding:4px 12px;font-family:monospace;'>{pf_acma}</td></tr>"
            f"</tbody></table>"
        )

    cors_creds_count = sum(1 for f in cors_findings if f.get("with_credentials"))
    cors_card = ""
    if cors_summary.get("probes_fired", 0):
        if cors_findings:
            cors_card = (
                f"<div class='card' style='border:2px solid #{'dc2626' if cors_creds_count else 'ea580c' if cors_findings else '16a34a'};'>"
                f"<h2 style='color:#{'dc2626' if cors_creds_count else 'ea580c'};'>🌐 Deep CORS Analysis — "
                f"{len(cors_findings)} misconfiguration(s) across {cors_summary.get('urls_tested',0)} URL(s)"
                f"{' <span style=background:#dc2626;color:white;padding:2px 10px;border-radius:12px;font-size:13px;>' + str(cors_creds_count) + ' with credentials</span>' if cors_creds_count else ''}"
                f"</h2>"
                f"<table><thead><tr><th>Severity</th><th>Technique</th><th>Origin Sent</th><th>ACAO Received</th><th>Credentials</th><th>Vary: Origin</th><th>URL</th></tr></thead>"
                f"<tbody>{cors_rows}</tbody></table>"
                f"{preflight_html}"
                f"<p style='margin-top:16px;font-size:13px;color:#059669;'>"
                f"<strong>Fix:</strong> Maintain a server-side origin allowlist. Never reflect the incoming Origin header. "
                f"Never combine <code>Access-Control-Allow-Credentials: true</code> with a wildcard or reflected origin. "
                f"Always include <code>Vary: Origin</code>.</p>"
                f"</div>"
            )
        else:
            cors_card = (
                f"<div class='card' style='border:2px solid #16a34a;'>"
                f"<h2 style='color:#16a34a;'>🌐 Deep CORS Analysis — ✅ No misconfigurations found</h2>"
                f"<p style='color:#6b7280;font-size:13px;'>Tested 10 bypass techniques across {cors_summary.get('urls_tested',0)} URL(s) — {cors_summary.get('probes_fired',0)} total probes.</p>"
                f"{preflight_html}"
                f"</div>"
            )

    xss_confirmed_count = sum(1 for f in xss_findings if f.get("confirmed_xss"))
    xss_card = (
        f"<div class='card' style='border:2px solid #ea580c;'>"
        f"<h2 style='color:#ea580c;'>🧬 Context-Aware XSS Analysis ({len(xss_findings)} reflection points, {xss_confirmed_count} confirmed)</h2>"
        f"<table><thead><tr><th>Parameter</th><th>Severity</th><th>Context</th><th>Confirmed</th><th>Working Payloads</th><th>WAF Bypasses</th><th>Recommendation</th></tr></thead>"
        f"<tbody>{xss_rows}</tbody></table></div>"
    ) if xss_findings else ""

    crawl_url_rows = "".join(
        f"<tr><td style='padding:5px 12px;font-family:monospace;font-size:12px;word-break:break-all;'>"
        f"<a href='{u}' style='color:#2563eb;text-decoration:none;'>{u}</a></td></tr>"
        for u in crawl_all_urls[:80]
    )
    crawl_param_tags = "".join(
        f"<span style='display:inline-block;background:#e0f2fe;color:#0369a1;padding:2px 10px;border-radius:12px;font-family:monospace;font-size:12px;margin:2px;'>{p}</span>"
        for p in crawl_params
    )
    crawl_form_rows = ""
    for form in crawl_forms[:30]:
        param_str = ", ".join(form.get("params", []))
        method = form.get("method", "GET")
        method_color = "#dc2626" if method == "POST" else "#2563eb"
        crawl_form_rows += (
            f"<tr>"
            f"<td style='padding:6px 12px;'><span style='background:{method_color};color:white;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600;'>{method}</span></td>"
            f"<td style='padding:6px 12px;font-family:monospace;font-size:12px;word-break:break-all;'>"
            f"<a href='{form.get('action','')}' style='color:#2563eb;text-decoration:none;'>{form.get('action','')}</a></td>"
            f"<td style='padding:6px 12px;font-family:monospace;font-size:11px;color:#6b7280;'>{param_str}</td></tr>"
        )
    crawl_path_rows = ""
    for f in crawl_path_findings:
        sev_color = SEVERITY_COLORS.get(f.get("severity", "INFO"), "#6b7280")
        crawl_path_rows += (
            f"<tr>"
            f"<td style='padding:7px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{f.get('severity','')}</span></td>"
            f"<td style='padding:7px 12px;font-family:monospace;font-size:12px;word-break:break-all;'>"
            f"<a href='{f.get('url','')}' style='color:#2563eb;text-decoration:none;'>{f.get('url','')}</a></td>"
            f"<td style='padding:7px 12px;font-size:12px;'>{f.get('type','')}</td>"
            f"<td style='padding:7px 12px;font-size:12px;color:#059669;'>{f.get('recommendation','')}</td>"
            f"</tr>"
        )

    # robots.txt card data
    robots_info   = crawl_data.get("robots_txt", {})
    blocked_urls  = crawl_data.get("blocked_by_robots", [])
    crawl_scope   = crawl_summary.get("scope", "domain")

    robots_section = ""
    if robots_info.get("found"):
        disallowed_list = "".join(
            f"<li style='font-family:monospace;font-size:12px;'>{p}</li>"
            for p in robots_info.get("disallowed", [])[:40]
        )
        sitemap_list = "".join(
            f"<li><a href='{s}' style='color:#2563eb;font-family:monospace;font-size:12px;'>{s}</a></li>"
            for s in robots_info.get("sitemaps", [])
        )
        n_dis = len(robots_info.get("disallowed", []))
        n_sm  = len(robots_info.get("sitemaps", []))
        robots_section = (
            f"<h3 style='font-size:15px;margin:16px 0 8px;color:#92400e;'>🤖 robots.txt ({n_dis} disallowed, {n_sm} sitemaps)</h3>"
            + (f"<ul style='margin:0 0 8px;padding-left:20px;'>{disallowed_list}</ul>" if disallowed_list else "")
            + (f"<ul style='margin:0;padding-left:20px;'>{sitemap_list}</ul>" if sitemap_list else "")
        )

    blocked_section = ""
    if blocked_urls:
        blocked_items = "".join(
            f"<li style='font-family:monospace;font-size:12px;color:#6b7280;'>{u}</li>"
            for u in blocked_urls[:20]
        )
        blocked_section = (
            f"<h3 style='font-size:15px;margin:16px 0 8px;color:#6b7280;'>🚫 Blocked by robots.txt ({len(blocked_urls)})</h3>"
            f"<ul style='margin:0;padding-left:20px;'>{blocked_items}</ul>"
        )

    crawl_card = ""
    if crawl_summary.get("pages_crawled", 0):
        scope_badge_color = "#7c3aed" if crawl_scope == "subdomains" else "#0891b2"
        crawl_parts = [
            f"<div class='card' style='border:2px solid #0891b2;'>"
            f"<h2 style='color:#0891b2;'>🕷 Passive Crawler — "
            f"{crawl_summary.get('pages_crawled',0)} pages &nbsp;"
            f"{crawl_summary.get('urls_found',0)} URLs &nbsp;"
            f"{crawl_summary.get('forms_found',0)} forms &nbsp;"
            f"{crawl_summary.get('params_found',0)} params"
            f"<span style='margin-left:12px;background:{scope_badge_color};color:white;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;'>scope: {crawl_scope}</span>"
            f"</h2>"
        ]
        if crawl_path_findings:
            crawl_parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#dc2626;'>🔍 Sensitive Paths Found ({len(crawl_path_findings)})</h3>"
                f"<table><thead><tr><th>Severity</th><th>URL</th><th>Type</th><th>Action</th></tr></thead>"
                f"<tbody>{crawl_path_rows}</tbody></table>"
            )
        if robots_section:
            crawl_parts.append(robots_section)
        if blocked_section:
            crawl_parts.append(blocked_section)
        if crawl_params:
            crawl_parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#0369a1;'>📋 Parameters Harvested ({len(crawl_params)})</h3>"
                f"<div style='margin-bottom:12px;'>{crawl_param_tags}</div>"
            )
        if crawl_forms:
            n_extra = len(crawl_forms) - 30
            crawl_parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;'>📝 Forms Found ({len(crawl_forms)})</h3>"
                f"<table><thead><tr><th>Method</th><th>Action URL</th><th>Parameters</th></tr></thead>"
                f"<tbody>{crawl_form_rows}</tbody></table>"
                + (f"<p style='color:#6b7280;font-size:12px;'>… and {n_extra} more forms</p>" if n_extra > 0 else "")
            )
        if crawl_all_urls:
            n_extra = len(crawl_all_urls) - 80
            crawl_parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;'>🔗 All URLs Discovered ({len(crawl_all_urls)})</h3>"
                f"<table><tbody>{crawl_url_rows}</tbody></table>"
                + (f"<p style='color:#6b7280;font-size:12px;'>… and {n_extra} more</p>" if n_extra > 0 else "")
            )
        crawl_parts.append("</div>")
        crawl_card = "".join(crawl_parts)

    js_secret_rows = ""
    for s in js_secrets:
        sev_color = SEVERITY_COLORS.get(s.get("severity", "HIGH"), "#ea580c")
        fname = s.get("js_file", "").split("/")[-1]
        js_secret_rows += (
            f"<tr>"
            f"<td style='padding:8px 12px;font-weight:600;'>{s.get('type','')}</td>"
            f"<td style='padding:8px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{s.get('severity','')}</span></td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:12px;color:#dc2626;font-weight:700;'>{s.get('value_redacted','')}</td>"
            f"<td style='padding:8px 12px;font-size:12px;color:#6b7280;'>{fname}:{s.get('line','')}</td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:11px;color:#374151;word-break:break-all;'>{s.get('excerpt','')[:100]}</td>"
            f"</tr>"
        )

    js_sink_rows = ""
    for sk in js_sinks:
        sev_color = SEVERITY_COLORS.get(sk.get("severity", "HIGH"), "#ea580c")
        fname = sk.get("js_file", "").split("/")[-1]
        js_sink_rows += (
            f"<tr>"
            f"<td style='padding:8px 12px;font-weight:600;'>{sk.get('type','')}</td>"
            f"<td style='padding:8px 12px;'><span style='background:{sev_color};color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;'>{sk.get('severity','')}</span></td>"
            f"<td style='padding:8px 12px;font-size:12px;color:#6b7280;'>{fname}:{sk.get('line','')}</td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:11px;color:#374151;word-break:break-all;'>{sk.get('excerpt','')[:120]}</td>"
            f"</tr>"
        )

    js_ep_rows = "".join(
        f"<tr><td style='padding:6px 12px;font-family:monospace;font-size:12px;word-break:break-all;'>{e.get('endpoint','')}</td>"
        f"<td style='padding:6px 12px;font-size:12px;color:#6b7280;'>{e.get('js_file','').split('/')[-1]}:{e.get('line','')}</td></tr>"
        for e in js_endpoints[:60]
    )

    js_files_list = "".join(
        f"<span style='display:inline-block;background:#f3f4f6;padding:3px 10px;border-radius:6px;font-family:monospace;font-size:12px;margin:3px;'>"
        f"<a href='{f.get('url','')}' style='color:#2563eb;text-decoration:none;'>{f.get('url','').split('/')[-1]}</a>"
        f" <span style='color:#9ca3af;'>{f.get('size',0):,}b</span></span>"
        for f in js_files
    )

    js_card = ""
    if js_files:
        parts = []
        parts.append(
            f"<div class='card' style='border:2px solid #7c3aed;'>"
            f"<h2 style='color:#7c3aed;'>📜 JavaScript Analysis"
            f" — {js_summary.get('files_scanned',0)} files, "
            f"{js_summary.get('total_secrets',0)} secrets, "
            f"{js_summary.get('total_sinks',0)} sinks, "
            f"{js_summary.get('total_endpoints',0)} endpoints</h2>"
        )
        parts.append(f"<p style='margin-bottom:12px;color:#6b7280;font-size:13px;'>JS files scanned: {js_files_list}</p>")
        if js_secrets:
            parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#dc2626;'>🔑 Exposed Secrets ({len(js_secrets)})</h3>"
                f"<table><thead><tr><th>Type</th><th>Severity</th><th>Value (redacted)</th><th>Location</th><th>Context</th></tr></thead>"
                f"<tbody>{js_secret_rows}</tbody></table>"
            )
        if js_sinks:
            parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#ea580c;'>⚠ Dangerous DOM Sinks ({len(js_sinks)})</h3>"
                f"<table><thead><tr><th>Sink</th><th>Severity</th><th>Location</th><th>Code Context</th></tr></thead>"
                f"<tbody>{js_sink_rows}</tbody></table>"
            )
        if js_source_maps:
            sm_link_parts = []
            for sm in js_source_maps:
                sm_url = sm.get("map_url", "")
                sm_link_parts.append(
                    f"<li><a href='{sm_url}' style='color:#2563eb;font-family:monospace;font-size:12px;'>{sm_url}</a></li>"
                )
            sm_links = "".join(sm_link_parts)
            parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#d97706;'>🗺 Source Maps ({len(js_source_maps)})</h3>"
                f"<ul style='margin:0;padding-left:20px;'>{sm_links}</ul>"
            )
        if js_endpoints:
            parts.append(
                f"<h3 style='font-size:15px;margin:16px 0 8px;color:#2563eb;'>🔗 Endpoints Found ({len(js_endpoints)})</h3>"
                f"<table><thead><tr><th>Endpoint</th><th>Source</th></tr></thead>"
                f"<tbody>{js_ep_rows}</tbody></table>"
            )
        parts.append("</div>")
        js_card = "".join(parts)

    takeover_card = (
        f"<div class='card' style='border:2px solid #dc2626;'>"
        f"<h2 style='color:#dc2626;'>🎯 Subdomain Takeover Candidates ({len(takeover_findings)})</h2>"
        f"<table><thead><tr><th>Subdomain</th><th>Service</th><th>Severity</th><th>CNAME Chain</th><th>Recommendation</th></tr></thead>"
        f"<tbody>{takeover_rows}</tbody></table></div>"
    ) if takeover_findings else ""

    dirs_rows = []
    for d in dirs:
        status_color = "#16a34a" if d["status"] == 200 else "#ea580c"
        dirs_rows.append(
            f"<tr><td style='padding:6px 12px;font-family:monospace;font-size:13px;word-break:break-all;'>{d['url']}</td>"
            f"<td style='padding:6px 12px;font-weight:600;color:{status_color};'>{d['status']}</td>"
            f"<td style='padding:6px 12px;color:#6b7280;'>{d.get('size', 0):,}</td></tr>"
        )
    dirs_html = "".join(dirs_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Bounty Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f3f4f6; color: #111827; }}
  .header {{ background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); color: white; padding: 40px; }}
  .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
  .header p {{ color: #c7d2fe; font-size: 14px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .card {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card h2 {{ font-size: 18px; margin-bottom: 16px; color: #1e1b4b; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .stat {{ background: white; border-radius: 10px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .stat .num {{ font-size: 32px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: #6b7280; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  thead tr {{ background: #f9fafb; }}
  th {{ padding: 10px 12px; text-align: left; font-weight: 600; color: #374151; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }}
  tbody tr:nth-child(odd) {{ background: #fafafa; }}
  tbody tr:hover {{ background: #f0f4ff; }}
  .risk-badge {{ display: inline-block; padding: 6px 20px; border-radius: 20px; font-weight: 700; font-size: 18px; color: white; background: {risk_color}; }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .tag {{ background: #dbeafe; color: #1e40af; padding: 4px 10px; border-radius: 6px; font-size: 13px; }}
  footer {{ text-align: center; color: #9ca3af; font-size: 12px; padding: 24px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Bug Bounty Scan Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; IP: <strong>{ip}</strong> &nbsp;|&nbsp; Scan: <strong>{scan_time}</strong></p>
</div>
<div class="container">

  <div class="stat-grid">
    <div class="stat"><div class="num" style="color:{risk_color};">{risk_label}</div><div class="label">Overall Risk</div></div>
    <div class="stat"><div class="num" style="color:#dc2626;">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#ea580c;">{counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#d97706;">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#2563eb;">{counts['LOW']}</div><div class="label">Low</div></div>
    <div class="stat"><div class="num">{len(open_ports)}</div><div class="label">Open Ports</div></div>
    <div class="stat"><div class="num">{len(subdomains)}</div><div class="label">Subdomains</div></div>
    <div class="stat"><div class="num" style="color:{'#dc2626' if takeover_findings else '#16a34a'};">{len(takeover_findings)}</div><div class="label">Takeovers</div></div>
    <div class="stat"><div class="num" style="color:{'#ea580c' if xss_confirmed_count else '#d97706' if xss_findings else '#16a34a'};">{xss_confirmed_count}</div><div class="label">XSS Confirmed</div></div>
    <div class="stat"><div class="num" style="color:{'#dc2626' if js_secrets else '#16a34a'};">{len(js_secrets)}</div><div class="label">JS Secrets</div></div>
    <div class="stat"><div class="num" style="color:#7c3aed;">{js_summary.get('files_scanned', 0)}</div><div class="label">JS Files</div></div>
    <div class="stat"><div class="num" style="color:#0891b2;">{crawl_summary.get('pages_crawled', 0)}</div><div class="label">Pages Crawled</div></div>
    <div class="stat"><div class="num" style="color:#0891b2;">{crawl_summary.get('urls_found', 0)}</div><div class="label">URLs Found</div></div>
    <div class="stat"><div class="num" style="color:{'#dc2626' if cors_creds_count else '#ea580c' if cors_findings else '#16a34a'};">{len(cors_findings)}</div><div class="label">CORS Issues</div></div>
    <div class="stat"><div class="num" style="color:{'#d97706' if waf_primary else '#16a34a'};">{waf_primary or '—'}</div><div class="label">WAF</div></div>
    <div class="stat"><div class="num" style="color:{'#dc2626' if smuggle_findings else '#16a34a'};">{'⚠' if smuggle_findings else '✓'}</div><div class="label">Smuggling</div></div>
  </div>

  {waf_card}

  {smuggle_card}

  {"<div class='card'><h2>🚨 Vulnerabilities & Findings</h2>" + findings_html + "</div>" if findings else "<div class='card'><h2>✅ No Vulnerabilities Found</h2><p style='color:#16a34a;'>No issues were detected during this scan.</p></div>"}

  {"<div class='card'><h2>🛠 Technologies Detected</h2><div class='tags'>" + "".join(f"<span class='tag'>{t}</span>" for t in techs) + "</div></div>" if techs else ""}

  {"<div class='card'><h2>🔌 Open Ports</h2><table><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th><th>Issues</th></tr></thead><tbody>" + ports_html + "</tbody></table></div>" if open_ports else ""}

  {"<div class='card'><h2>🌐 DNS Records</h2><table><thead><tr><th>Type</th><th>Records</th></tr></thead><tbody>" + dns_html + "</tbody></table></div>" if dns_html else ""}

  {crawl_card}

  {cors_card}

  {js_card}

  {xss_card}

  {takeover_card}

  {"<div class='card'><h2>🔗 Subdomains (" + str(len(subdomains)) + ")</h2><table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>" + subdomains_html + "</tbody></table></div>" if subdomains else ""}

  {"<div class='card'><h2>📁 Discovered Paths</h2><table><thead><tr><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>" + dirs_html + "</tbody></table></div>" if dirs else ""}

</div>
<footer>Generated by BugBountyTool &nbsp;|&nbsp; {scan_time}</footer>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return output_path


# ── OWASP Top 10 Compliance Report ─────────────────────────────────────────────

OWASP_CATEGORIES = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "color": "#dc2626",
        "desc": "Restrictions on authenticated users are not properly enforced.",
        "remediation": "Apply deny-by-default, enforce access control on server side, log and alert failures.",
        "finding_types": {"open_redirect", "access_control", "idor", "forced_browsing"},
        "result_keys": [("redirect", "findings")],
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "color": "#7c3aed",
        "desc": "Failures related to cryptography exposing sensitive data.",
        "remediation": "Enforce HTTPS everywhere, use strong TLS (1.2+), set HSTS, avoid weak ciphers.",
        "finding_types": {"tls", "https", "hsts", "crypto", "ssl", "http_redirect"},
        "result_keys": [("owasp", "A02")],
    },
    {
        "id": "A03",
        "name": "Injection",
        "color": "#b91c1c",
        "desc": "User-supplied data is not validated and sent to an interpreter.",
        "remediation": "Use parameterized queries, validate/encode all inputs, apply WAF rules for injection patterns.",
        "finding_types": {"xss", "sqli", "lfi", "injection", "command_injection"},
        "result_keys": [
            ("vulns", "xss_issues"),
            ("vulns", "sqli_issues"),
            ("vulns", "lfi_issues"),
            ("xss", "findings"),
        ],
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "color": "#92400e",
        "desc": "Missing or ineffective control design and threat modelling.",
        "remediation": "Adopt secure design patterns, threat model during design phase, use security champions.",
        "finding_types": {"insecure_design"},
        "result_keys": [],
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "color": "#d97706",
        "desc": "Missing security hardening, open cloud storage, verbose errors, unnecessary features enabled.",
        "remediation": "Harden all environments, remove default accounts, review and update security configurations.",
        "finding_types": {"header", "misconfiguration", "cors", "default_page", "verbose_error"},
        "result_keys": [
            ("vulns", "header_issues"),
            ("vulns", "http_method_issues"),
            ("cors_deep", "findings"),
            ("owasp", "A05"),
        ],
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "color": "#b45309",
        "desc": "Outdated software with known vulnerabilities used in the application.",
        "remediation": "Continuously inventory components, subscribe to CVE feeds, update dependencies regularly.",
        "finding_types": {"outdated", "vulnerable_component", "eol"},
        "result_keys": [("owasp", "A06")],
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "color": "#0369a1",
        "desc": "Authentication and session management weaknesses.",
        "remediation": "Implement MFA, use strong session management, avoid default credentials.",
        "finding_types": {"auth", "session", "default_creds", "cookie"},
        "result_keys": [("owasp", "A07")],
    },
    {
        "id": "A08",
        "name": "Software and Data Integrity Failures",
        "color": "#6d28d9",
        "desc": "Code and infrastructure without integrity verification (CI/CD, auto-updates, insecure deserialization).",
        "remediation": "Use digital signatures, verify checksums, use SRI for CDN assets, review CI/CD pipelines.",
        "finding_types": {"integrity", "sri", "csp", "deserialization"},
        "result_keys": [("owasp", "A08")],
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "color": "#0f766e",
        "desc": "Insufficient logging and monitoring enabling attackers to persist undetected.",
        "remediation": "Log all authentication events, enable alerting, centralize logs, test incident response.",
        "finding_types": {"log_exposure", "logging", "monitoring"},
        "result_keys": [("owasp", "A09")],
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "color": "#be185d",
        "desc": "Web application fetches a remote resource from attacker-controlled URL.",
        "remediation": "Validate and sanitize all user-supplied URLs, use allowlists, disable HTTP redirects.",
        "finding_types": {"ssrf"},
        "result_keys": [("owasp", "A10")],
    },
]


def _gather_owasp_findings(results: dict, category: dict) -> list[dict]:
    """Pull findings relevant to an OWASP category from all result sections."""
    out: list[dict] = []

    for section_key, sub_key in category["result_keys"]:
        section = results.get(section_key, {})
        if isinstance(section, dict):
            items = section.get(sub_key, [])
            if isinstance(items, list):
                out.extend(items)

    all_findings = _all_findings(results)
    for f in all_findings:
        ftype = (f.get("type") or "").lower().replace(" ", "_")
        if any(k in ftype for k in category["finding_types"]):
            if f not in out:
                out.append(f)

    return out


def save_owasp_html(results: dict, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    target    = results.get("target", "Unknown")
    scan_time = results.get("scan_time", "")
    ip        = results.get("ip", "N/A")

    category_cards = ""
    total_findings = 0
    affected_count = 0

    for cat in OWASP_CATEGORIES:
        findings = _gather_owasp_findings(results, cat)
        total_findings += len(findings)
        status_color  = cat["color"] if findings else "#16a34a"
        status_label  = f"⚠ {len(findings)} FINDING{'S' if len(findings) != 1 else ''}" if findings else "✓ NOT DETECTED"
        if findings:
            affected_count += 1

        findings_html = ""
        for f in findings:
            sev   = f.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            findings_html += f"""
            <div style="border-left:3px solid {color};background:#f9fafb;padding:12px 16px;margin:8px 0;border-radius:0 6px 6px 0;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <strong style="font-size:13px;">{f.get("type", "Finding")}</strong>
                {_severity_badge(sev)}
              </div>
              <p style="margin:3px 0;font-size:13px;color:#374151;">{f.get("description","")}</p>
              {"<p style='margin:3px 0;font-size:12px;color:#6b7280;word-break:break-all;'><strong>URL:</strong> " + f.get("url","") + "</p>" if f.get("url") else ""}
              {"<p style='margin:3px 0;font-size:12px;color:#059669;'><strong>Fix:</strong> " + f.get("recommendation","") + "</p>" if f.get("recommendation") else ""}
            </div>"""

        if not findings_html:
            findings_html = "<p style='color:#16a34a;padding:8px 0;'>No issues detected for this category.</p>"

        category_cards += f"""
        <div style="border:1px solid #e5e7eb;border-radius:10px;margin-bottom:24px;overflow:hidden;">
          <div style="background:{cat['color']};color:white;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;">
            <div>
              <span style="font-size:18px;font-weight:700;">{cat['id']} — {cat['name']}</span>
              <p style="margin:4px 0 0;font-size:13px;opacity:0.9;">{cat['desc']}</p>
            </div>
            <div style="background:rgba(0,0,0,0.25);padding:6px 14px;border-radius:20px;font-weight:700;font-size:13px;white-space:nowrap;">
              {status_label}
            </div>
          </div>
          <div style="padding:16px 20px;">
            <p style="margin:0 0 12px;font-size:13px;color:#374151;">
              <strong>Remediation:</strong> {cat['remediation']}
            </p>
            {findings_html}
          </div>
        </div>"""

    overall_color = "#dc2626" if affected_count >= 5 else "#d97706" if affected_count >= 2 else "#16a34a"
    overall_label = f"{affected_count} / 10 categories affected"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP Top 10 Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f0f0f; color: #e5e7eb; }}
  .topbar {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 40px 48px; border-bottom: 2px solid #dc2626; }}
  .topbar h1 {{ font-size: 28px; color: #fff; font-weight: 800; letter-spacing: 1px; }}
  .topbar h1 span {{ color: #ef4444; }}
  .topbar .meta {{ font-size: 13px; color: #9ca3af; margin-top: 8px; }}
  .overview {{ display: flex; gap: 20px; padding: 32px 48px; flex-wrap: wrap; background: #111; border-bottom: 1px solid #222; }}
  .stat-card {{ background: #1a1a1a; border: 1px solid #2d2d2d; border-radius: 10px; padding: 20px 28px; min-width: 160px; text-align: center; }}
  .stat-card .num {{ font-size: 32px; font-weight: 800; }}
  .stat-card .lbl {{ font-size: 12px; color: #6b7280; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .content {{ padding: 32px 48px; max-width: 1100px; margin: 0 auto; }}
  .section-title {{ font-size: 20px; font-weight: 700; margin: 0 0 20px; color: #fff; border-left: 4px solid #dc2626; padding-left: 14px; }}
  footer {{ text-align: center; padding: 24px; font-size: 12px; color: #4b5563; border-top: 1px solid #1f2937; }}
</style>
</head>
<body>

<div class="topbar">
  <h1>🛡 OWASP Top 10 <span>(2021)</span> — Compliance Report</h1>
  <div class="meta">
    Target: <strong style="color:#e5e7eb;">{target}</strong> &nbsp;|&nbsp;
    IP: <strong style="color:#e5e7eb;">{ip}</strong> &nbsp;|&nbsp;
    Scan: <strong style="color:#e5e7eb;">{scan_time}</strong> &nbsp;|&nbsp;
    Tool: <strong style="color:#ef4444;">Hacker00X1 — Bug Bounty Tool Kit</strong>
  </div>
</div>

<div class="overview">
  <div class="stat-card">
    <div class="num" style="color:{overall_color};">{affected_count}</div>
    <div class="lbl">Categories Affected</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#ef4444;">{total_findings}</div>
    <div class="lbl">Total Findings</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#16a34a;">{10 - affected_count}</div>
    <div class="lbl">Categories Passed</div>
  </div>
  <div class="stat-card" style="flex:1;text-align:left;padding:20px 24px;">
    <div style="font-size:13px;color:#9ca3af;margin-bottom:4px;">Overall Status</div>
    <div style="font-size:18px;font-weight:700;color:{overall_color};">{overall_label}</div>
  </div>
</div>

<div class="content">
  <div class="section-title">OWASP Top 10 (2021) — Category Breakdown</div>
  {category_cards}
</div>

<footer>
  Generated by Hacker00X1 — Bug Bounty Tool Kit &nbsp;|&nbsp; {scan_time}
</footer>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return output_path


def save_hackerone_md(results: dict, output_path: str) -> dict:
    """Generate HackerOne-ready markdown reports from scan results.

    Produces:
    - output_path              : master index / executive summary
    - <stem>_findings/<n>_<slug>.md : one standalone H1 submission file per
                                      Critical / High / Medium finding

    Returns a dict: {"summary": str, "findings_dir": str, "count": int}
    """
    from pathlib import Path
    from urllib.parse import urlparse
    import re as _re

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    target    = results.get("target", "Unknown")
    domain    = results.get("domain", target)
    scan_time = results.get("scan_time", "")
    ip        = results.get("ip", "N/A")
    duration  = results.get("scan_duration_seconds", 0)

    _PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def _collect_all() -> list[dict]:
        all_f: list[dict] = []
        for section in ["header_issues", "cors_issues", "open_redirect_issues",
                         "xss_issues", "sqli_issues", "lfi_issues", "sensitive_files",
                         "http_method_issues"]:
            all_f.extend(results.get("vulns", {}).get(section, []))
        all_f.extend(results.get("takeover", {}).get("findings", []))
        all_f.extend(results.get("xss", {}).get("findings", []))
        all_f.extend(results.get("js", {}).get("converted_findings", []))
        all_f.extend(results.get("crawl", {}).get("path_findings", []))
        all_f.extend(results.get("cors_deep", {}).get("converted_findings", []))
        all_f.extend(results.get("smuggle", {}).get("converted_findings", []))
        all_f.extend(results.get("redirect", {}).get("converted_findings", []))
        all_f.extend(results.get("owasp", {}).get("summary", {}).get("all_findings", []))
        for adv_key in ["sqli", "auth", "pathtraversal", "cmdinject", "bizlogic",
                         "infodisclosure", "accesscontrol", "fileupload", "raceconditions",
                         "ssrf", "xxe", "nosqli", "apitest", "webcache"]:
            all_f.extend(results.get(adv_key, {}).get("findings", []))
        seen_keys: set = set()
        deduped: list[dict] = []
        for f in all_f:
            k = (f.get("type", ""), f.get("url", ""), f.get("severity", ""))
            if k not in seen_keys:
                seen_keys.add(k)
                deduped.append(f)
        return sorted(deduped, key=lambda x: _PRIORITY.get(x.get("severity", "INFO"), 99))

    _SEVERITY_TO_H1 = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "INFO":     "none",
    }

    _CWE_MAP = {
        "reflected xss":      ("CWE-79",  "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"),
        "stored xss":         ("CWE-79",  "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"),
        "xss":                ("CWE-79",  "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"),
        "sql injection":      ("CWE-89",  "Improper Neutralization of Special Elements used in an SQL Command"),
        "sqli":               ("CWE-89",  "Improper Neutralization of Special Elements used in an SQL Command"),
        "ssrf":               ("CWE-918", "Server-Side Request Forgery (SSRF)"),
        "open redirect":      ("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "redirect":           ("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "cors":               ("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "path traversal":     ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "lfi":                ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "command injection":  ("CWE-78",  "Improper Neutralization of Special Elements used in an OS Command"),
        "xxe":                ("CWE-611", "Improper Restriction of XML External Entity Reference"),
        "idor":               ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "access control":     ("CWE-284", "Improper Access Control"),
        "broken access":      ("CWE-284", "Improper Access Control"),
        "subdomain takeover": ("CWE-350", "Reliance on Reverse DNS Resolution for a Security-Critical Action"),
        "takeover":           ("CWE-350", "Reliance on Reverse DNS Resolution for a Security-Critical Action"),
        "csrf":               ("CWE-352", "Cross-Site Request Forgery (CSRF)"),
        "file upload":        ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "http smuggling":     ("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "smuggling":          ("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "information disclosure": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "sensitive":          ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "race condition":     ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"),
        "nosql":              ("CWE-943", "Improper Neutralization of Special Elements in Data Query Logic"),
        "auth":               ("CWE-287", "Improper Authentication"),
        "authentication":     ("CWE-287", "Improper Authentication"),
        "security header":    ("CWE-693", "Protection Mechanism Failure"),
        "header":             ("CWE-693", "Protection Mechanism Failure"),
        "web cache":          ("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
        "cache":              ("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
    }

    _CVSS_DATA: dict[str, dict] = {
        "sql injection":      {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "sqli":               {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "command injection":  {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "xxe":                {"score": "9.1",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "nosql":              {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "http smuggling":     {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "smuggling":          {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "file upload":        {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "auth":               {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "authentication":     {"score": "9.8",  "rating": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "ssrf":               {"score": "8.6",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
        "stored xss":         {"score": "8.8",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"},
        "subdomain takeover": {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "takeover":           {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "cors":               {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"},
        "idor":               {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "access control":     {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "broken access":      {"score": "8.1",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "race condition":     {"score": "7.5",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "path traversal":     {"score": "7.5",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "lfi":                {"score": "7.5",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "information disclosure": {"score": "7.5", "rating": "High",  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "reflected xss":      {"score": "6.1",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "xss":                {"score": "6.1",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "open redirect":      {"score": "6.1",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "redirect":           {"score": "6.1",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "csrf":               {"score": "6.5",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},
        "sensitive":          {"score": "5.3",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        "security header":    {"score": "5.4",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "header":             {"score": "5.4",  "rating": "Medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "web cache":          {"score": "7.5",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "cache":              {"score": "7.5",  "rating": "High",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    }

    def _cwe_for(finding: dict) -> tuple[str, str]:
        ftype = (finding.get("type") or "").lower()
        for key, val in _CWE_MAP.items():
            if key in ftype:
                return val
        return ("CWE-Unknown", "Unknown Weakness")

    def _cvss_for(finding: dict) -> dict:
        ftype = (finding.get("type") or "").lower()
        if finding.get("cvss"):
            return {"score": str(finding["cvss"]), "rating": finding.get("severity", "").title(), "vector": ""}
        for key, val in _CVSS_DATA.items():
            if key in ftype:
                return val
        return {}

    def _title_for(finding: dict) -> str:
        ftype = (finding.get("type") or "").lower()
        url     = finding.get("url", "")
        param   = finding.get("param", "")
        path    = ""
        if url:
            _p = urlparse(url)
            path = _p.path or "/"
        param_str = f" via `{param}` parameter" if param else ""
        path_str  = f" at `{path}`"              if path and path not in ("/", "") else ""
        if "sql injection" in ftype or "sqli" in ftype:
            return f"SQL Injection{param_str}{path_str} on {domain}"
        if "reflected xss" in ftype:
            return f"Reflected Cross-Site Scripting (XSS){param_str}{path_str}"
        if "stored xss" in ftype:
            return f"Stored Cross-Site Scripting (XSS){path_str}"
        if "xss" in ftype:
            return f"Cross-Site Scripting (XSS){param_str}{path_str}"
        if "ssrf" in ftype:
            return f"Server-Side Request Forgery (SSRF){param_str}{path_str}"
        if "command injection" in ftype or "cmdinject" in ftype:
            return f"OS Command Injection{param_str}{path_str}"
        if "subdomain takeover" in ftype or "takeover" in ftype:
            sub = finding.get("subdomain", domain)
            svc = finding.get("service", "")
            return f"Subdomain Takeover of `{sub}`" + (f" via {svc}" if svc else "")
        if "cors" in ftype:
            return f"CORS Misconfiguration Allows Cross-Origin Data Reads{path_str}"
        if "open redirect" in ftype or "redirect" in ftype:
            return f"Open Redirect{param_str}{path_str}"
        if "path traversal" in ftype or "lfi" in ftype:
            return f"Path Traversal / Local File Inclusion (LFI){param_str}{path_str}"
        if "file upload" in ftype:
            return f"Unrestricted File Upload Allows Remote Code Execution{path_str}"
        if "http smuggling" in ftype or "smuggling" in ftype:
            variant = finding.get("variant", "")
            return f"HTTP Request Smuggling ({variant}){path_str}" if variant else f"HTTP Request Smuggling{path_str}"
        if "xxe" in ftype:
            return f"XML External Entity (XXE) Injection{path_str}"
        if "nosql" in ftype:
            return f"NoSQL Injection{param_str}{path_str}"
        if "idor" in ftype or "access control" in ftype or "broken access" in ftype:
            return f"Insecure Direct Object Reference (IDOR) / Broken Access Control{path_str}"
        if "race condition" in ftype:
            return f"Race Condition Vulnerability{path_str}"
        if "authentication" in ftype or "auth" in ftype:
            return f"Authentication Bypass / Weak Authentication{path_str}"
        if "information disclosure" in ftype or "sensitive" in ftype:
            return f"Sensitive Information Disclosure{path_str}"
        if "security header" in ftype or "header" in ftype:
            hdr = finding.get("header", "")
            return f"Missing Security Header: `{hdr}`" if hdr else f"Missing Security Headers on {domain}"
        if "web cache" in ftype or "cache" in ftype:
            return f"Web Cache Deception / Poisoning{path_str}"
        return f"{finding.get('type', 'Vulnerability')}{path_str}"

    def _steps_for(finding: dict) -> list[str]:
        ftype   = (finding.get("type") or "").lower()
        url     = finding.get("url", "") or target
        param   = finding.get("param", "")
        payload = finding.get("payload", "")
        method  = finding.get("method", "GET").upper()

        if "xss" in ftype:
            p = payload or "<script>alert(document.domain)</script>"
            return [
                f"Open a browser and navigate to `{url}`.",
                f"Locate the `{param}` input field or URL parameter." if param else "Locate a user-controlled input field or URL parameter.",
                f"Enter the following XSS payload: `{p}`",
                "Submit the form or send the crafted request.",
                "Observe that the JavaScript executes in the browser context.",
                "Confirm that `alert()` fires, proving the input is reflected without sanitization.",
            ]
        if "sql" in ftype:
            p = payload or "' OR '1'='1"
            return [
                f"Send a `{method}` request to `{url}`.",
                f"Inject the following SQL payload into the `{param}` parameter: `{p}`" if param else f"Inject the payload `{p}` into a user-controlled parameter.",
                "Submit the request via browser, `curl`, or Burp Suite.",
                "Observe a database error message or unexpected data rows in the response.",
                "To confirm blind injection, try a time-based payload (e.g. `'; WAITFOR DELAY '0:0:5'--`) and observe the response delay.",
            ]
        if "ssrf" in ftype:
            return [
                f"Send a `{method}` request to `{url}`.",
                f"Set the `{param}` parameter to an internal address: `http://169.254.169.254/latest/meta-data/`" if param else "Inject an internal URL (e.g. `http://169.254.169.254/latest/meta-data/`) into the relevant parameter.",
                "Inspect the response body.",
                "Observe that the server fetches and returns content from the internal resource.",
                "Confirm cloud metadata, internal service data, or an internal network response is visible.",
            ]
        if "cors" in ftype:
            origin_sent = finding.get("origin_sent", "https://evil.com")
            return [
                f"Send a `{method}` request to `{url}` with the request header `Origin: {origin_sent}`.",
                "Inspect the response headers.",
                f"Observe that `Access-Control-Allow-Origin: {origin_sent}` is reflected.",
                "If `Access-Control-Allow-Credentials: true` is also present, craft a credentialed cross-origin fetch from an attacker-controlled page.",
                "Observe that the full response body is accessible to the cross-origin script.",
            ]
        if "redirect" in ftype:
            p = payload or "//evil.com"
            redir_url = f"`{url}?{param}={p}`" if param else f"`{url}?next={p}`"
            return [
                f"Navigate to {redir_url} in a browser.",
                "Observe that the application redirects to the attacker-controlled domain without validation.",
                "Confirm by checking the final URL in the browser address bar.",
            ]
        if "path traversal" in ftype or "lfi" in ftype:
            p = payload or "../../../../etc/passwd"
            return [
                f"Send a `{method}` request to `{url}`.",
                f"Set the `{param}` parameter to: `{p}`" if param else f"Inject the traversal payload `{p}` into the file path parameter.",
                "Inspect the response body.",
                "Observe the contents of the targeted file (e.g. `/etc/passwd` entries such as `root:x:0:0:root`).",
            ]
        if "takeover" in ftype or "subdomain" in ftype:
            sub  = finding.get("subdomain", url)
            svc  = finding.get("service", "the detected hosting service")
            return [
                f"Verify that `{sub}` has a dangling CNAME pointing to {svc} with no live resource behind it (e.g. via `dig CNAME {sub}`).",
                f"Create a free account at {svc} and claim the matching project, repository, or bucket name that the CNAME resolves to.",
                f"Upload a proof-of-concept page to the claimed resource.",
                f"Navigate to `{sub}` in a browser.",
                "Observe that you now control the content served at the subdomain.",
            ]
        if "file upload" in ftype:
            return [
                f"Navigate to the file upload feature at `{url}`.",
                "Prepare a malicious file — for example a PHP web shell (`<?php system($_GET['cmd']); ?>`) saved with a `.php` extension, or use extension-bypass techniques (e.g. `.php5`, double extension, null byte).",
                "Upload the file using the application's upload form.",
                "Determine the URL of the uploaded file (check response body or common upload paths).",
                "Send a GET request to the uploaded file URL (e.g. `curl 'https://{domain}/uploads/shell.php?cmd=id'`).",
                "Observe that the server executes the file and returns the command output.",
            ]
        if "smuggling" in ftype:
            variant = finding.get("variant", "CL.TE")
            return [
                f"Send a specially crafted HTTP/{variant} smuggling request to `{url}` using raw sockets or Burp Suite's HTTP Request Smuggler extension.",
                "Follow up with a normal request from a different session.",
                "Observe that the follow-up request is partially interpreted as part of the smuggled request body.",
                "Confirm by observing unexpected responses, session hijacking, or WAF bypass.",
            ]
        if "xxe" in ftype:
            return [
                f"Send a POST request to `{url}` with `Content-Type: application/xml`.",
                "Include the following DOCTYPE declaration in the XML body:",
                "  `<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>`",
                "Reference the entity in the body: `<element>&xxe;</element>`",
                "Inspect the response.",
                "Observe that the contents of `/etc/passwd` are returned, confirming XXE injection.",
            ]
        if "header" in ftype:
            hdr = finding.get("header", "the security header")
            return [
                f"Open a terminal and run: `curl -sI {url}`",
                f"Inspect the response headers and note the absence of the `{hdr}` header.",
                "Alternatively, use browser DevTools (F12 → Network → select the request → Headers tab) and confirm the header is missing from the response.",
            ]
        steps = [
            f"Send a `{method}` request to `{url}`.",
            "Identify the vulnerability described in the Summary section.",
            "Confirm the impact by reproducing the described behaviour.",
        ]
        if payload:
            steps.insert(1, f"Use the following payload: `{payload}`")
        return steps

    def _impact_for(finding: dict, sev: str) -> str:
        ftype = (finding.get("type") or "").lower()
        if finding.get("impact"):
            return finding["impact"]
        if "xss" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Steal session cookies / tokens** and take over victim accounts without needing credentials (if cookies lack the `HttpOnly` flag)\n"
                "- **Perform actions on behalf of the victim** (CSRF-equivalent using XSS)\n"
                "- **Inject a fake login form** to harvest credentials\n"
                "- **Redirect victims** to phishing or malware-serving pages\n"
                "- **Capture keystrokes** on the affected page\n\n"
                "Severity escalates significantly if the XSS fires in an admin context."
            )
        if "sql" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Dump the entire database**, including usernames, password hashes, PII, and application secrets\n"
                "- **Bypass authentication** by manipulating the WHERE clause of login queries\n"
                "- **Modify or delete arbitrary records** (UPDATE / DELETE / DROP)\n"
                "- **Achieve Remote Code Execution** via `xp_cmdshell` (MSSQL) or `INTO OUTFILE` (MySQL) if the database user has sufficient privileges\n\n"
                "This is a critical risk to data confidentiality, integrity, and application availability."
            )
        if "ssrf" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Access cloud metadata services** (AWS `169.254.169.254`, GCP `metadata.google.internal`) to steal IAM credentials and instance roles\n"
                "- **Probe and attack internal network services** that are not reachable from the internet\n"
                "- **Bypass IP allowlists** and firewall rules by using the server as a proxy\n"
                "- **Read data from unauthenticated internal services** such as Redis, Elasticsearch, and Memcached\n\n"
                "In cloud environments, SSRF commonly leads to full account takeover via stolen IAM credentials."
            )
        if "cors" in ftype:
            with_creds = finding.get("with_credentials", False)
            if with_creds:
                return (
                    "Because `Access-Control-Allow-Credentials: true` is combined with a reflected origin, an attacker can:\n\n"
                    "- **Read sensitive authenticated API responses** from a victim's browser session — including personal data, tokens, and account details\n"
                    "- **Perform authenticated state-changing actions** on behalf of the victim from an attacker-controlled page\n"
                    "- **Bypass CSRF protections** that rely solely on the same-origin policy\n\n"
                    "The attacker only needs to trick the victim into visiting a page they control."
                )
            return (
                "This misconfiguration allows attacker-controlled origins to read API responses, potentially exposing:\n\n"
                "- **Sensitive user data** returned by API endpoints\n"
                "- **Authentication or CSRF tokens** embedded in responses\n"
                "- **Internal application state** that should not be accessible cross-origin"
            )
        if "redirect" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Conduct phishing attacks**: craft a URL that appears to originate from the trusted domain but silently redirects victims to a malicious site\n"
                "- **Steal OAuth tokens**: abuse the redirect URI in OAuth flows to capture authorization codes on an attacker-controlled server\n"
                "- **Bypass SSRF allowlists** that permit requests to the trusted domain by chaining with server-side fetchers\n\n"
                "Users are significantly more likely to click a link from a trusted domain, making this a high-value phishing vector."
            )
        if "path traversal" in ftype or "lfi" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Read arbitrary server files**, including `/etc/passwd`, SSH private keys, application source code, and credentials\n"
                "- **Extract secrets** such as database connection strings and API keys from configuration files\n"
                "- **Escalate to Remote Code Execution** by combining with file upload vulnerabilities or log poisoning (PHP environments)\n\n"
                "Log poisoning: write a PHP payload to an accessible log file, then include it via LFI to execute arbitrary code."
            )
        if "takeover" in ftype:
            return (
                "A successful subdomain takeover allows the attacker to:\n\n"
                "- **Host arbitrary content** under the victim's trusted domain, bypassing origin trust boundaries\n"
                "- **Steal cookies** scoped to the parent domain (if the `Domain` attribute is set broadly)\n"
                "- **Conduct phishing attacks** with a pixel-perfect replica on a trusted subdomain\n"
                "- **Intercept OAuth redirect URIs** and steal authorization codes if the subdomain is a registered redirect URI\n"
                "- **Abuse Content Security Policy** trust relationships defined for the parent domain"
            )
        if "file upload" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Upload a web shell** (PHP, ASP, JSP) and achieve Remote Code Execution on the server\n"
                "- **Read all server files**, environment variables, and stored credentials\n"
                "- **Pivot laterally** through the internal network from the compromised server\n"
                "- **Establish persistence** by planting backdoors or cron jobs\n\n"
                "Unrestricted file upload is one of the most severe vulnerability classes and typically results in full server compromise."
            )
        if "smuggling" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Hijack victim sessions** by poisoning the request queue and capturing other users' requests\n"
                "- **Bypass WAFs, rate limiters, and access controls** that rely on HTTP parsing consistency\n"
                "- **Exploit XSS** that would otherwise be blocked by CSP or `HttpOnly` cookies\n"
                "- **Poison shared CDN caches** to serve malicious responses to all users\n\n"
                "This is a server-level vulnerability that affects every user of the application."
            )
        if "xxe" in ftype:
            return (
                "An attacker who exploits this vulnerability can:\n\n"
                "- **Read arbitrary files** from the server via external entity references (e.g. `/etc/passwd`, `/proc/self/environ`)\n"
                "- **Perform SSRF** by resolving HTTP-based external entities to probe internal services\n"
                "- **Cause Denial of Service** via recursive entity expansion (billion-laughs attack)\n"
                "- **Exfiltrate data out-of-band** using DNS or HTTP callbacks in blind XXE scenarios"
            )
        if "header" in ftype:
            hdr = finding.get("header", "")
            hl  = hdr.lower()
            if "csp" in hl or "content-security" in hl:
                return "Without a Content-Security-Policy header the application cannot restrict which scripts execute in users' browsers, dramatically lowering the bar for XSS exploitation."
            if "hsts" in hl:
                return "Without HTTP Strict Transport Security, an active network attacker can strip HTTPS to HTTP (SSL stripping), intercepting all traffic in cleartext — including session cookies and credentials."
            if "x-frame" in hl:
                return "Without X-Frame-Options or a `frame-ancestors` CSP directive, the application is vulnerable to clickjacking, where the attacker overlays an invisible iframe of the target page on top of a deceptive page and tricks the victim into clicking."
            return f"The missing `{hdr}` header leaves the application without the browser-side protection it provides, exposing users to the attacks it is designed to prevent."
        _defaults = {
            "CRITICAL": "An attacker can fully compromise the affected system, leading to unauthorized access to all data, remote code execution, or complete service disruption.",
            "HIGH":     "An attacker can access sensitive data or escalate privileges in a way that significantly compromises the security of the application and its users.",
            "MEDIUM":   "An attacker can cause limited harm — partial data exposure, minor privilege escalation, or degraded service — that still requires prompt remediation.",
        }
        return _defaults.get(sev, "The security impact of this issue requires manual verification.")

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def _higher_sev(a: str, b: str) -> str:
        return a if _SEV_ORDER.get(a, 99) <= _SEV_ORDER.get(b, 99) else b

    def _na_risk(finding: dict) -> tuple[str, str]:
        """Return (risk_level, advice) for a confirmed finding.
        risk_level: 'low'    → reliably rewarded, submit with confidence
                    'medium' → rewarded by many programs, include extra context
                    'high'   → almost always N/A, do not submit
        """
        ftype = (finding.get("type") or "").lower()
        hdr   = (finding.get("header") or "").lower()
        sev   = finding.get("severity", "INFO")

        for t in ("reflected xss", "stored xss", "xss",
                  "sql injection", "sqli",
                  "path traversal", "lfi",
                  "command injection", "cmdinject",
                  "xxe", "ssrf",
                  "subdomain takeover", "takeover",
                  "file upload",
                  "race condition",
                  "nosql injection", "nosqli"):
            if t in ftype:
                return ("low", "Reliably rewarded — submit with confidence.")

        if "cors" in ftype:
            if finding.get("with_credentials"):
                return ("low", "CORS with credentials=true is reliably rewarded.")
            return ("high",
                    "CORS with wildcard (*) and no credentials is almost always N/A on public endpoints. "
                    "Only submit if the endpoint returns authenticated or sensitive user data.")

        if "auth" in ftype or "authentication" in ftype:
            return ("low", "Authentication bypass is reliably rewarded.")

        if "idor" in ftype or "access control" in ftype or "broken access" in ftype:
            return ("low", "IDOR / broken access control is reliably rewarded.")

        if "http smuggling" in ftype or "smuggling" in ftype:
            return ("low", "HTTP request smuggling is reliably rewarded.")

        if "information disclosure" in ftype or "sensitive" in ftype:
            if sev in ("CRITICAL", "HIGH"):
                return ("low", "High-severity info disclosure (credentials, keys, tokens) is reliably rewarded.")
            return ("medium",
                    "Include evidence that the exposed data is sensitive and directly usable by an attacker "
                    "(e.g. API key, database password, private key).")

        if "open redirect" in ftype or "redirect" in ftype:
            return ("medium",
                    "Open redirects are rewarded by many programs. Strengthen the report by demonstrating "
                    "an OAuth token theft scenario or phishing with the trusted domain in the URL.")

        if "web cache" in ftype or "cache" in ftype:
            return ("medium",
                    "Web cache poisoning is rewarded when you demonstrate user impact. "
                    "Include proof of a poisoned response being served to a second, clean request.")

        if "header" in ftype or "security header" in ftype:
            if any(h in hdr for h in ("x-content-type-options", "x-content-type")):
                return ("high", "Missing X-Content-Type-Options is almost always N/A — skip this finding.")
            if "referrer" in hdr:
                return ("high", "Missing Referrer-Policy is almost always N/A — skip this finding.")
            if "x-xss-protection" in hdr:
                return ("high", "X-XSS-Protection is deprecated and always N/A — skip this finding.")
            if "x-powered-by" in hdr or "server" in hdr:
                return ("high", "Server/technology version disclosure is almost always N/A — skip this finding.")
            if "x-frame-options" in hdr or "frame" in hdr:
                return ("medium",
                        "Missing X-Frame-Options is often N/A. To avoid N/A, include a working clickjacking "
                        "PoC on a sensitive action (e.g. password change, fund transfer, account deletion).")
            if "content-security-policy" in hdr or "csp" in hdr:
                return ("medium",
                        "Missing CSP alone is low/medium impact. Pair it with an XSS finding for higher "
                        "severity, or demonstrate how its absence enables a concrete attack.")
            if "strict-transport-security" in hdr or "hsts" in hdr:
                return ("medium",
                        "Missing HSTS is rewarded by some programs. Check the program policy; "
                        "mention SSL stripping as the concrete attack scenario.")
            return ("high",
                    "Generic missing-header findings are almost always N/A unless directly enabling an "
                    "exploitable attack. Verify the program accepts this class of finding.")

        if sev == "CRITICAL":
            return ("low", "Critical severity findings are reliably rewarded.")
        if sev == "HIGH":
            return ("low", "High severity findings are generally rewarded.")
        return ("medium",
                "Verify this finding is in-scope and has clear exploitable impact before submitting.")

    def _upgrade_severity(finding: dict) -> tuple[str, str, dict]:
        """Return (new_severity, upgrade_reason, new_cvss) for a confirmed finding.
        Upgrades when live evidence shows higher exploitability than the original rating.
        Returns original severity and empty reason/cvss if no upgrade is needed.
        """
        ftype   = (finding.get("type") or "").lower()
        sev     = finding.get("severity", "MEDIUM")
        ev_note = (finding.get("evidence", {}).get("validation_note") or "").lower()
        ev_resp = (finding.get("evidence", {}).get("response") or "").lower()
        combined = ev_note + ev_resp

        new_sev  = sev
        reason   = ""
        new_cvss: dict = {}

        if ("sql" in ftype or "sqli" in ftype) and ("sql error" in combined or "ora-" in combined
                or "sqlstate" in combined or "syntax error" in combined):
            new_sev  = _higher_sev("CRITICAL", sev)
            reason   = "Severity upgraded to Critical: live SQL error confirmed in response — database is injectable and data is at immediate risk."
            new_cvss = {"score": "9.8", "rating": "Critical",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}

        elif "cors" in ftype and finding.get("with_credentials"):
            new_sev  = _higher_sev("HIGH", sev)
            reason   = "Severity upgraded to High: CORS confirmed with Access-Control-Allow-Credentials: true — authenticated cross-origin data reads are possible."
            new_cvss = {"score": "8.1", "rating": "High",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"}

        elif ("lfi" in ftype or "path traversal" in ftype) and (
                "file content" in ev_note or "root:x" in combined or "etc/passwd" in combined):
            new_sev  = _higher_sev("HIGH", sev)
            reason   = "Severity upgraded to High: local file read confirmed — /etc/passwd or system file content was returned in the live response."
            new_cvss = {"score": "7.5", "rating": "High",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}

        elif "stored xss" in ftype and ("unescaped" in ev_note or "payload" in ev_note):
            new_sev  = _higher_sev("HIGH", sev)
            reason   = "Severity upgraded to High: stored XSS payload confirmed — executes for every user who views the affected page."
            new_cvss = {"score": "8.8", "rating": "High",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"}

        elif "xss" in ftype and ("unescaped" in ev_note or "payload" in ev_note):
            new_sev  = _higher_sev("MEDIUM", sev)
            reason   = "Confirmed: XSS payload found unescaped in live HTTP response — JavaScript execution in victim browser is verified."
            new_cvss = {"score": "6.1", "rating": "Medium",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}

        elif ("takeover" in ftype or "subdomain" in ftype) and "confirmed" in ev_note:
            new_sev  = _higher_sev("HIGH", sev)
            reason   = "Severity upgraded to High: subdomain takeover confirmed with a live platform-specific signature in the HTTP response."
            new_cvss = {"score": "8.1", "rating": "High",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}

        elif "file upload" in ftype:
            new_sev  = _higher_sev("CRITICAL", sev)
            reason   = "Severity upgraded to Critical: unrestricted file upload confirmed — server-side code execution is a direct consequence."
            new_cvss = {"score": "9.8", "rating": "Critical",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}

        if new_sev == sev:
            reason = ""
        return (new_sev, reason, new_cvss)

    all_findings = _collect_all()
    _submittable_sevs = ("CRITICAL", "HIGH", "MEDIUM")

    for f in all_findings:
        if f.get("confidence") == "confirmed":
            new_sev, up_reason, new_cvss = _upgrade_severity(f)
            if new_sev != f.get("severity") and up_reason:
                f["severity_original"] = f["severity"]
                f["severity"]          = new_sev
                f["severity_upgraded"] = True
                f["upgrade_reason"]    = up_reason
                if new_cvss:
                    f["cvss_upgraded"] = new_cvss
            na_risk, na_advice = _na_risk(f)
            f["na_risk"]   = na_risk
            f["na_advice"] = na_advice

    confirmed_low    = [f for f in all_findings
                        if f.get("confidence") == "confirmed"
                        and f.get("severity", "INFO") in _submittable_sevs
                        and f.get("na_risk", "medium") == "low"]
    confirmed_medium = [f for f in all_findings
                        if f.get("confidence") == "confirmed"
                        and f.get("severity", "INFO") in _submittable_sevs
                        and f.get("na_risk", "medium") == "medium"]
    skip_findings    = ([f for f in all_findings
                         if f.get("confidence") == "confirmed"
                         and f.get("severity", "INFO") in _submittable_sevs
                         and f.get("na_risk", "medium") == "high"]
                        + [f for f in all_findings
                           if f.get("confidence") == "likely"
                           and f.get("severity", "INFO") in _submittable_sevs])

    reportable = confirmed_low + confirmed_medium

    counts: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    findings_dir = Path(output_path).parent / (Path(output_path).stem + "_findings")
    if reportable:
        findings_dir.mkdir(parents=True, exist_ok=True)

    def _slug(text: str) -> str:
        return _re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:40]

    waf_name   = results.get("waf", {}).get("primary_waf")
    subdomains = results.get("recon", {}).get("subdomains", [])
    open_ports = results.get("ports", {}).get("open_ports", [])
    techs      = results.get("web", {}).get("technologies", [])

    individual_paths: list[str] = []

    for idx, finding in enumerate(reportable, 1):
        sev       = finding.get("severity", "MEDIUM")
        ftype     = finding.get("type", "Vulnerability")
        url       = finding.get("url", target)
        rec       = finding.get("recommendation", "")
        desc      = finding.get("description", "")
        h1_sev    = _SEVERITY_TO_H1.get(sev, "none")
        cwe_id, cwe_name = _cwe_for(finding)
        cvss      = finding.get("cvss_upgraded") or _cvss_for(finding)
        title     = _title_for(finding)
        steps     = _steps_for(finding)
        impact    = _impact_for(finding, sev)
        up_reason = finding.get("upgrade_reason", "")
        na_advice = finding.get("na_advice", "")
        na_risk   = finding.get("na_risk", "medium")
        orig_sev  = finding.get("severity_original", "")

        fname = f"{idx:02d}_{sev.lower()}_{_slug(ftype)}.md"
        fpath = findings_dir / fname
        individual_paths.append(str(fpath))

        reward_badge = {
            "low":    "✅ HIGH reward potential — reliably rewarded on HackerOne",
            "medium": "⚠️  MEDIUM reward potential — include extra context (see note below)",
        }.get(na_risk, "")

        f_lines: list[str] = [
            f"# {title}",
            "",
        ]
        if reward_badge:
            f_lines += [f"> **{reward_badge}**", ""]
        f_lines += [
            "| Field | Value |",
            "|-------|-------|",
            f"| **Target** | `{domain}` |",
            f"| **Asset** | `{url}` |",
            f"| **Severity** | {sev.title()} (HackerOne: `{h1_sev}`) |",
        ]
        if orig_sev:
            f_lines.append(f"| **Original Severity** | {orig_sev.title()} → upgraded based on evidence |")
        if cvss:
            f_lines.append(f"| **CVSS 3.1 Score** | {cvss['score']} ({cvss['rating']}) |")
            if cvss.get("vector"):
                f_lines.append(f"| **CVSS Vector** | `{cvss['vector']}` |")
        f_lines += [
            f"| **Weakness** | {cwe_id} — {cwe_name} |",
            f"| **Scan Date** | {scan_time} |",
            "",
            "---",
            "",
            "## Summary",
            "",
            desc if desc else f"A {sev.lower()}-severity **{ftype}** vulnerability was identified on `{domain}` at `{url}`.",
            "",
            "## Steps To Reproduce",
            "",
        ]
        for i, step in enumerate(steps, 1):
            f_lines.append(f"{i}. {step}")
        f_lines += [
            "",
            "## Supporting Material / References",
            "",
        ]
        extras: list[str] = []
        for key, label in [("param", "Affected Parameter"), ("payload", "Payload Used"),
                            ("method", "HTTP Method"), ("service", "Service"),
                            ("variant", "Variant"), ("origin_sent", "Origin Sent"),
                            ("acao", "Access-Control-Allow-Origin"), ("filename", "Filename"),
                            ("header", "Missing Header"), ("scheme", "Scheme")]:
            val = finding.get(key)
            if val:
                extras.append(f"- **{label}:** `{val}`")
        if extras:
            f_lines += extras
        else:
            f_lines.append(f"- Verified during automated scan of `{domain}` on {scan_time}.")
        f_lines += [
            "",
            "## Impact",
            "",
            impact,
        ]
        if rec:
            f_lines += [
                "",
                "## Recommended Fix",
                "",
                rec,
            ]

        if up_reason:
            f_lines += [
                "",
                "## Severity Upgrade — Escalated From Evidence",
                "",
                f"**{up_reason}**",
                "",
                f"> Original scanner severity was **{orig_sev.title()}**. "
                f"This was upgraded to **{sev.title()}** because the live HTTP response "
                "contains direct proof of higher impact. The CVSS score above reflects the upgraded rating.",
            ]

        if na_risk == "medium" and na_advice:
            f_lines += [
                "",
                "## Maximize Reward Potential",
                "",
                f"> ⚠️  {na_advice}",
                "",
                "> **Before submitting:** Add the extra context described above to avoid an N/A triage decision.",
            ]

        h1_note = finding.get("h1_note", "")
        if h1_note:
            f_lines += [
                "",
                "## 📋 HackerOne Submission Tips",
                "",
                f"> {h1_note}",
            ]

        evidence   = finding.get("evidence", {})
        confidence = finding.get("confidence", "")
        ev_request  = evidence.get("request", "")
        ev_response = evidence.get("response", "")
        ev_note     = evidence.get("validation_note", "")
        ev_status   = evidence.get("http_status", "")
        ev_ms       = evidence.get("response_time_ms", "")

        if ev_note or ev_request or ev_response:
            conf_label = {
                "confirmed": "✔ Confirmed — reproduced with live HTTP evidence",
                "likely":    "⚠ Likely — strong indicator; OOB/manual verification needed",
            }.get(confidence, "")

            f_lines += ["", "## Evidence", ""]
            if conf_label:
                f_lines += [f"**Validation status:** {conf_label}", ""]
            if ev_note:
                f_lines += [f"**Validation note:** {ev_note}", ""]
            if ev_status:
                f_lines += [f"**HTTP Status:** `{ev_status}`" + (f"  |  **Response time:** `{ev_ms} ms`" if ev_ms else ""), ""]
            if ev_request:
                f_lines += [
                    "**HTTP Request sent during validation:**",
                    "```http",
                    ev_request.strip(),
                    "```",
                    "",
                ]
            if ev_response:
                f_lines += [
                    "**HTTP Response (relevant excerpt):**",
                    "```http",
                    ev_response.strip()[:1200],
                    "```",
                    "",
                ]

        f_lines += [
            "",
            "---",
            "",
            "> **Important:** This report was generated by an automated scanner. Verify this finding manually before submitting to a bug bounty program. Only test targets for which you have explicit written authorization.",
            "",
            f"*Generated by Hacker00X1 Bug Bounty Tool Kit | {scan_time}*",
        ]

        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(f_lines) + "\n")

    summary_lines: list[str] = [
        "# Bug Bounty Report — Vulnerability Scan Summary",
        "",
        f"> **Target:** `{target}`  ",
        f"> **IP:** `{ip}`  ",
        f"> **Scan Date:** {scan_time}  ",
        f"> **Scan Duration:** {duration}s  ",
        f"> **Tool:** Hacker00X1 — Bug Bounty Tool Kit  ",
        "> **Note:** Automated scan — verify each finding manually before submitting.",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {counts.get('CRITICAL', 0)} |",
        f"| High     | {counts.get('HIGH', 0)} |",
        f"| Medium   | {counts.get('MEDIUM', 0)} |",
        f"| Low      | {counts.get('LOW', 0)} |",
        f"| Info     | {counts.get('INFO', 0)} |",
        "",
    ]

    if waf_name or subdomains or open_ports or techs:
        summary_lines += ["## Reconnaissance Summary", ""]
        if waf_name:
            summary_lines.append(f"- **WAF Detected:** {waf_name}")
        if subdomains:
            summary_lines.append(f"- **Subdomains Found:** {len(subdomains)}")
        if open_ports:
            ports_str = ", ".join(str(p.get("port", "?")) for p in open_ports[:15])
            summary_lines.append(f"- **Open Ports:** {ports_str}")
        if techs:
            summary_lines.append(f"- **Technologies:** {', '.join(techs)}")
        summary_lines += ["", "---", ""]

    if not confirmed_low and not confirmed_medium and not skip_findings:
        summary_lines += [
            "## Findings",
            "",
            "> No confirmed findings. Run the scan with a wider scope or check targets manually.",
            "",
        ]
    else:
        def _summary_row(idx: int, finding: dict, show_file: bool = True) -> str:
            sev       = finding.get("severity", "MEDIUM")
            ftype     = finding.get("type", "Vulnerability")
            url       = finding.get("url", target)
            cwe_id, _ = _cwe_for(finding)
            cvss      = finding.get("cvss_upgraded") or _cvss_for(finding)
            title     = _title_for(finding)
            score_str = cvss.get("score", "—") if cvss else "—"
            upgraded  = "⬆" if finding.get("severity_upgraded") else ""
            if show_file:
                fname = f"{idx:02d}_{sev.lower()}_{_slug(ftype)}.md"
                return (f"| {idx} | **{sev.title()}**{upgraded} | {title} | `{url}` | "
                        f"{score_str} | {cwe_id} | [{fname}]({findings_dir.name}/{fname}) |")
            else:
                note = (finding.get("na_advice") or finding.get("evidence", {}).get("validation_note", "") or "Verify before submitting")[:90]
                conf = finding.get("confidence", "likely")
                return (f"| {idx} | **{sev.title()}** | {title} | `{url}` | "
                        f"{score_str} | {cwe_id} | {conf.title()} | {note} |")

        if confirmed_low:
            summary_lines += [
                f"## ✅ Ready to Submit — High Reward Potential ({len(confirmed_low)})",
                "",
                "> These findings were **re-tested with a live HTTP request**, confirmed with concrete evidence,",
                "> and belong to vulnerability classes that are **reliably rewarded** on HackerOne.",
                "> Each has its own submission file in `" + findings_dir.name + "/`. Submit one report per finding.",
                "> ⬆ = severity was upgraded from the original scanner rating based on confirmed evidence.",
                "",
                "| # | Severity | Vulnerability | Asset | CVSS | CWE | Submission File |",
                "|---|----------|--------------|-------|------|-----|----------------|",
            ]
            for idx, finding in enumerate(confirmed_low, 1):
                summary_lines.append(_summary_row(idx, finding, show_file=True))
            summary_lines += [""]

        if confirmed_medium:
            offset = len(confirmed_low)
            summary_lines += [
                f"## ⚠️  Submit With Extra Context — Medium Reward Potential ({len(confirmed_medium)})",
                "",
                "> These findings are **confirmed** but belong to classes that programs sometimes N/A",
                "> without additional context. Read the **Maximize Reward Potential** section in each",
                "> submission file and add the suggested evidence before submitting.",
                "",
                "| # | Severity | Vulnerability | Asset | CVSS | CWE | Submission File |",
                "|---|----------|--------------|-------|------|-----|----------------|",
            ]
            for i, finding in enumerate(confirmed_medium, 1):
                summary_lines.append(_summary_row(offset + i, finding, show_file=True))
            summary_lines += [""]

        if skip_findings:
            summary_lines += [
                f"## 🚫 Do Not Submit — High N/A Risk or Unverified ({len(skip_findings)})",
                "",
                "> These findings are either **unverifiable without OOB tools** (SSRF, blind SQLi, XXE,",
                "> command injection) or belong to vulnerability classes that programs **almost always N/A**",
                "> (missing X-Content-Type-Options, wildcard CORS on public APIs, deprecated headers, etc.).",
                "> **Submitting these will hurt your reputation and signal score on HackerOne.**",
                "",
                "| # | Severity | Vulnerability | Asset | CVSS | CWE | Status | Note |",
                "|---|----------|--------------|-------|------|-----|--------|------|",
            ]
            for idx, finding in enumerate(skip_findings, 1):
                summary_lines.append(_summary_row(idx, finding, show_file=False))
            summary_lines += [""]

    scope_excluded = results.get("scope_excluded", [])
    scope_data     = results.get("scope_data", {})
    if scope_excluded:
        prog_label = scope_data.get("program") or "Program scope file"
        summary_lines += [
            f"## 🎯 Out of Scope — Not Submitted ({len(scope_excluded)})",
            "",
            f"> These findings were detected but **removed before validation and reporting**",
            f"> because their asset URL does not match the **{prog_label}** scope definition.",
            "> Submitting out-of-scope findings causes immediate N/A and can result in program bans.",
            "",
            "| # | Severity | Vulnerability | Asset | Reason |",
            "|---|----------|--------------|-------|--------|",
        ]
        for i, f in enumerate(scope_excluded[:50], 1):
            sev    = f.get("severity", "?")
            ftype  = f.get("type", "Finding")[:40]
            url    = (f.get("url") or "")[:70]
            reason = f.get("out_of_scope_reason", "Does not match scope patterns")
            summary_lines.append(f"| {i} | {sev.title()} | {ftype} | `{url}` | {reason} |")
        if len(scope_excluded) > 50:
            summary_lines.append(f"| … | | | | {len(scope_excluded) - 50} more findings not shown |")
        summary_lines += [""]

    summary_lines += [
        "---",
        "",
        "## Submission Instructions (Confirmed Findings Only)",
        "",
        "Each **confirmed** finding has its own ready-to-submit file in the `" + findings_dir.name + "/` folder.",
        "Submit **one report per finding** to the program's HackerOne page:",
        "",
        "1. Go to the program's H1 page → **Submit Report**",
        "2. Fill in **Title** from the `#` heading of the individual file",
        "3. Select **Asset**, **Weakness** (CWE), and **Severity** from the metadata table",
        "4. Paste the **Summary**, **Steps To Reproduce**, **Evidence**, and **Impact** sections",
        "5. Attach any screenshots or additional HTTP request/response captures",
        "6. Submit — then follow up with the triage team if no response within 7 days",
        "",
        "> Only submit reports for in-scope targets. Follow the program's disclosure policy.",
        "> **Do not submit findings from the OOB section above until manually confirmed.**",
        "",
        "---",
        "",
        f"*Generated by Hacker00X1 Bug Bounty Tool Kit | {scan_time}*",
    ]

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(summary_lines) + "\n")

    return {"summary": output_path, "findings_dir": str(findings_dir), "count": len(reportable)}
