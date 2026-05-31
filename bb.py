#!/usr/bin/env python3

"""
BugBountyTool — Automated reconnaissance and vulnerability scanner
Usage: python bb.py <target> [options]
"""

import os
import sys
import time
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
from datetime import datetime
from pathlib import Path

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
    import yaml
    import dns.resolver
except ImportError:
    print("Dependencies not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from data import recon, portscan, webfuzz, vulns, reporter, takeover, xss_gen, jsanalyzer, crawler, cors, waf, smuggler, redirect, owasp, endpoint_scanner
from data import sqli, auth, pathtraversal, cmdinject, bizlogic, infodisclosure, accesscontrol, fileupload, raceconditions, ssrf, xxe, nosqli, apitest, webcache

console = Console()

_ASCII_ART = """\
[bold red]██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗ ██╗[/bold red]
[bold red]██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚██╗██╔╝███║[/bold red]
[bold red]███████║███████║██║     █████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║ ╚███╔╝  ██║[/bold red]
[bold red]██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ██╔██╗  ██║[/bold red]
[bold red]██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝██╔╝ ██╗ ██║[/bold red]
[dim red]╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝[/dim red]"""

BANNER = "[bold red]  Hacker00X1[/bold red]  [dim]─  Bug Bounty Tool Kit  |  Recon · Scan · Exploit · Report[/dim]"


def _print_big_banner(target: str = ""):
    subtitle = f"[dim]target:[/dim] [bold green]{target}[/bold green]" if target else "[dim]no target set[/dim]"
    panel = Panel(
        _ASCII_ART + "\n\n[dim]  Bug Bounty Tool Kit  ─  Recon · Scan · Exploit · Report[/dim]",
        border_style="bold red",
        padding=(0, 2),
        subtitle=subtitle,
    )
    console.print()
    console.print(panel)

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "dim",
}


def load_config(config_path: str = None) -> dict:
    default_config = Path(__file__).parent / "config.yaml"
    path = Path(config_path) if config_path else default_config
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f)
    return {}


def normalize_target(target: str) -> tuple[str, str]:
    """Returns (domain, base_url)"""
    if not target.startswith(("http://", "https://")):
        target_url = f"https://{target}"
    else:
        target_url = target

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]
    return domain, target_url


def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    with open(p) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def print_section(title: str, emoji: str = ""):
    console.print(f"\n[bold white on blue]  {emoji} {title}  [/bold white on blue]")


def print_finding(finding: dict):
    sev = finding.get("severity", "INFO")
    style = SEVERITY_STYLES.get(sev, "")
    console.print(f"  [{style}][{sev}][/{style}] {finding.get('description', '')}")
    if finding.get("url"):
        console.print(f"         [dim]↳ {finding['url']}[/dim]")
    if finding.get("recommendation"):
        console.print(f"         [green]✓ {finding['recommendation']}[/green]")


def _run_single_scan(target: str, cfg: dict, opts: dict) -> dict:
    """Run the full scan pipeline on one target. Returns a result-summary dict."""
    output_dir          = opts["output_dir"]
    threads             = opts.get("threads")
    timeout             = opts.get("timeout")
    no_report           = opts["no_report"]
    json_only           = opts["json_only"]
    report_owasp        = opts["report_owasp"]
    export_h1           = opts["export_h1"]
    quiet               = opts["quiet"]
    skip_waf            = opts["skip_waf"]
    skip_ports          = opts["skip_ports"]
    skip_subdomains     = opts["skip_subdomains"]
    skip_dirfuzz        = opts["skip_dirfuzz"]
    skip_vulns          = opts["skip_vulns"]
    skip_takeover       = opts["skip_takeover"]
    skip_xss_gen        = opts["skip_xss_gen"]
    skip_js             = opts["skip_js"]
    skip_cors_deep      = opts["skip_cors_deep"]
    skip_smuggle        = opts["skip_smuggle"]
    skip_redirect       = opts["skip_redirect"]
    ignore_ssl          = opts["ignore_ssl"]
    skip_crawl          = opts["skip_crawl"]
    crawl_depth         = opts["crawl_depth"]
    crawl_pages         = opts["crawl_pages"]
    crawl_scope         = opts["crawl_scope"]
    crawl_delay         = opts["crawl_delay"]
    no_robots           = opts["no_robots"]
    ports               = opts["ports"]
    wordlist_subdomains = opts["wordlist_subdomains"]
    wordlist_dirs       = opts["wordlist_dirs"]
    skip_owasp          = opts["skip_owasp"]
    skip_sqli           = opts["skip_sqli"]
    skip_auth           = opts["skip_auth"]
    skip_pathtraversal  = opts["skip_pathtraversal"]
    skip_cmdinject      = opts["skip_cmdinject"]
    skip_bizlogic       = opts["skip_bizlogic"]
    skip_infodisclosure = opts["skip_infodisclosure"]
    skip_accesscontrol  = opts["skip_accesscontrol"]
    skip_fileupload     = opts["skip_fileupload"]
    skip_raceconditions = opts["skip_raceconditions"]
    skip_ssrf           = opts["skip_ssrf"]
    skip_xxe            = opts["skip_xxe"]
    skip_nosqli         = opts["skip_nosqli"]
    skip_apitest        = opts["skip_apitest"]
    skip_webcache       = opts["skip_webcache"]
    skip_validate       = opts.get("skip_validate", False)
    triage_mode         = opts.get("triage_mode", False)
    scope_file          = opts.get("scope_file")

    scan_cfg  = cfg.get("scan", {})
    port_cfg  = cfg.get("ports", {})
    recon_cfg = cfg.get("recon", {})
    vuln_cfg  = cfg.get("vulns", {})

    _threads    = threads or scan_cfg.get("threads", 30)
    _timeout    = timeout or scan_cfg.get("timeout", 4)
    _ua         = scan_cfg.get("user_agent", "BugBountyTool/1.0")
    _ssl_verify = not ignore_ssl

    if ignore_ssl:
        import ssl as _ssl
        _ssl._create_default_https_context = _ssl._create_unverified_context
        console.print("[yellow]⚠  SSL verification disabled — scanning all certificates.[/yellow]")

    if not quiet:
        _print_big_banner(target)
        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Threads:[/bold] {_threads}  [bold]Timeout:[/bold] {_timeout}s  [bold]Ports:[/bold] {ports}",
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
        ))

    domain, base_url = normalize_target(target)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_start = time.time()

    results = {
        "target": target,
        "domain": domain,
        "base_url": base_url,
        "scan_time": scan_time,
        "ip": None,
        "recon": {},
        "ports": {},
        "web": {},
        "vulns": {},
        "takeover": {},
        "xss": {},
        "js": {},
        "crawl": {},
        "cors_deep": {},
        "waf": {},
        "smuggle": {},
        "redirect": {},
        "owasp": {},
        "sqli": {}, "auth": {}, "pathtraversal": {}, "cmdinject": {},
        "bizlogic": {}, "infodisclosure": {}, "accesscontrol": {},
        "fileupload": {}, "raceconditions": {}, "ssrf": {},
        "xxe": {}, "nosqli": {}, "apitest": {}, "webcache": {},
    }

    # ── IP Resolution ─────────────────────────────────────────────────────────
    console.print(f"\n[dim]Resolving {domain}...[/dim]")
    ip = recon.get_ip(domain)
    results["ip"] = ip
    if ip:
        console.print(f"[green]✓[/green] Resolved to [bold]{ip}[/bold]")
        rdns = recon.reverse_dns(ip)
        if rdns:
            console.print(f"[green]✓[/green] Reverse DNS: [dim]{rdns}[/dim]")
    else:
        console.print(f"[red]✗[/red] Could not resolve {domain}")

    # ── Checkpoint Init ────────────────────────────────────────────────────────
    from data import checkpoint as _ckpt_mod
    _ckpt_path = _ckpt_mod.get_path(output_dir, domain)
    _ckpt_done: set  = set()
    _ckpt_saved: dict = {}
    if resume:
        _ckpt_saved = _ckpt_mod.load(_ckpt_path)
        _ckpt_done  = set(_ckpt_saved.get("completed_phases", []))
        if _ckpt_done:
            console.print(
                Panel(
                    f"[bold green]Resuming scan[/bold green] for [bold]{domain}[/bold]\n"
                    f"  Checkpoint : [dim]{_ckpt_path}[/dim]\n"
                    f"  Created    : [dim]{_ckpt_saved.get('created_at', '?')}[/dim]\n"
                    f"  Completed  : [bold cyan]{', '.join(sorted(_ckpt_done))}[/bold cyan]\n\n"
                    f"  Skipping completed phases — running only remaining work.",
                    border_style="green",
                    title="[bold]⏩ Resume Mode[/bold]",
                )
            )
        else:
            console.print("[dim]  --resume: no checkpoint found for this target, starting fresh[/dim]")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1/4 — PARALLEL: WAF · DNS · Subdomain Enum · Port Scan
    # All four tasks are fully independent and fire simultaneously.
    # ═══════════════════════════════════════════════════════════════════════════
    _p1_fns: dict = {}

    if not skip_waf:
        _p1_fns["waf"] = lambda: waf.fingerprint(base_url, timeout=_timeout, user_agent=_ua)

    _p1_fns["dns"] = lambda: recon.dns_lookup(
        domain, recon_cfg.get("dns_records", ["A", "AAAA", "MX", "NS", "TXT", "CNAME"])
    )

    if not skip_subdomains:
        def _enum_subs(_threads=_threads):
            _crt = recon.crtsh_subdomains(domain)
            _wl  = wordlist_subdomains or str(Path(__file__).parent / "wordlists" / "subdomains.txt")
            _b   = recon.brute_subdomains(domain, load_wordlist(_wl), threads=_threads, timeout=_timeout)
            _seen = {(s.get("subdomain", s) if isinstance(s, dict) else s) for s in _b}
            for s in _crt:
                if s not in _seen:
                    _b.append({"subdomain": s, "ip": recon.get_ip(s) or ""})
                    _seen.add(s)
            return _b
        _p1_fns["subdomains"] = _enum_subs

    if not skip_ports and ip:
        def _scan_ports(_threads=_threads):
            if ports == "common":
                _pl = port_cfg.get("common", [])
            elif ports == "extended":
                _pl = port_cfg.get("common", []) + port_cfg.get("extended", [])
            else:
                _pl = list(range(1, 65536))
            _op = portscan.scan_ports(ip, _pl, threads=min(_threads * 2, 50), timeout=_timeout)
            for _p in _op:
                _p["service_vulns"] = portscan.detect_service_vulns(_p)
            return _op, _pl
        _p1_fns["ports"] = _scan_ports

    _p1_data: dict = {}
    if "p1" in _ckpt_done:
        _p1_data = _ckpt_saved.get("p1_data") or {}
        console.print(f"\n[bold cyan]━━ Phase 1/4[/bold cyan] — [dim]⏩ loaded from checkpoint[/dim]")
    else:
        _n_p1 = len(_p1_fns)
        console.print(
            f"\n[bold cyan]━━ Phase 1/4[/bold cyan] — Parallel initial recon "
            f"([bold]{_n_p1}[/bold] tasks: " + ", ".join(k.upper() for k in _p1_fns) + ")"
        )
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console, transient=True) as _prog:
            _pt1 = _prog.add_task("Phase 1 recon…", total=_n_p1)
            with ThreadPoolExecutor(max_workers=_n_p1) as _pool:
                _p1_futs = {name: _pool.submit(fn) for name, fn in _p1_fns.items()}
                for _ in _as_completed(_p1_futs.values()):
                    _prog.advance(_pt1)
        for _name, _fut in _p1_futs.items():
            try:
                _p1_data[_name] = _fut.result()
            except Exception as _e:
                _p1_data[_name] = None
                if not quiet:
                    console.print(f"[red]  ✗ Phase-1 {_name}: {_e}[/red]")
        _ckpt_mod.save(_ckpt_path, _ckpt_saved, phase="p1", data=_p1_data, domain=domain, base_url=base_url)
        _ckpt_saved = _ckpt_mod.load(_ckpt_path)

    # ── Display WAF ────────────────────────────────────────────────────────────
    waf_results: dict = _p1_data.get("waf") or {}
    results["waf"] = waf_results
    if not skip_waf:
        print_section("WAF & Rate-Limit Detection", "🛡")
        _primary_waf = waf_results.get("primary_waf")
        _detected    = waf_results.get("detected", [])
        _rl          = waf_results.get("rate_limit", {})
        _rec_threads = waf_results.get("recommended_threads", _threads)
        _rec_delay   = waf_results.get("recommended_delay_ms", 0)

        if _primary_waf:
            _top = _detected[0]
            console.print(
                f"[bold yellow]⚠  WAF detected:[/bold yellow] [bold]{_primary_waf}[/bold]  "
                f"[dim](confidence {_top['confidence']}%  |  {_top['signals_matched']} signals)[/dim]"
            )
            if len(_detected) > 1 and not quiet:
                for _d in _detected[1:]:
                    console.print(f"  [dim]Also matched:[/dim] {_d['name']} ({_d['confidence']}%)")
        else:
            console.print("[green]✓ No known WAF signature matched[/green]")

        if _rl.get("triggered"):
            console.print(
                f"  [bold red]Rate-limit triggered![/bold red] "
                f"{_rl['blocked_count']}/{_rl['burst_size']} requests blocked "
                f"({_rl['pct_blocked']}%)  first block at request #{_rl.get('first_block_at', '?')}"
            )
        else:
            console.print(f"  [dim]Rate-limit burst ({_rl.get('burst_size', 0)} requests): not triggered[/dim]")

        if _primary_waf and _rec_threads < _threads:
            console.print(
                f"  [yellow]Auto-tuning:[/yellow] threads {_threads} → {_rec_threads}, "
                f"crawl-delay 0 → {_rec_delay} ms  "
                f"[dim]({waf_results.get('notes', '')})[/dim]"
            )
            _threads    = _rec_threads
            crawl_delay = _rec_delay
        elif not quiet:
            console.print(f"  [dim]{waf_results.get('notes', '')}[/dim]")

    # ── Display DNS ────────────────────────────────────────────────────────────
    dns_results = _p1_data.get("dns") or {}
    results["recon"]["dns"] = dns_results
    print_section("Reconnaissance", "🔍")
    _dns_tbl = Table(box=box.SIMPLE, show_header=True)
    _dns_tbl.add_column("Type", style="bold cyan", width=8)
    _dns_tbl.add_column("Records")
    for _rtype, _records in dns_results.items():
        if _records:
            _dns_tbl.add_row(_rtype, "\n".join(_records))
    console.print(_dns_tbl)

    # ── Display Subdomains ─────────────────────────────────────────────────────
    brute_subs: list = []
    if not skip_subdomains:
        brute_subs = _p1_data.get("subdomains") or []
        results["recon"]["subdomains"] = brute_subs
        if brute_subs:
            console.print(f"[green]✓[/green] Found [bold]{len(brute_subs)}[/bold] subdomains")
            if not quiet:
                _sub_tbl = Table(box=box.SIMPLE, show_header=True)
                _sub_tbl.add_column("Subdomain", style="bold")
                _sub_tbl.add_column("IP", style="dim")
                for _s in brute_subs[:20]:
                    _sub_tbl.add_row(
                        _s.get("subdomain", _s) if isinstance(_s, dict) else _s,
                        _s.get("ip", "") if isinstance(_s, dict) else ""
                    )
                if len(brute_subs) > 20:
                    _sub_tbl.add_row(f"... and {len(brute_subs) - 20} more", "")
                console.print(_sub_tbl)
        else:
            console.print("[dim]No subdomains found[/dim]")

    # ── Display Port Scan ──────────────────────────────────────────────────────
    open_ports: list = []
    if not skip_ports and ip:
        if _p1_data.get("ports"):
            open_ports, _port_list = _p1_data["ports"]
            results["ports"]["open_ports"] = open_ports
            print_section("Port Scanning", "🔌")
            console.print(f"[dim]Scanned {len(_port_list)} ports on {ip}[/dim]")
            if open_ports:
                _pt = Table(box=box.SIMPLE, show_header=True)
                _pt.add_column("Port", style="bold cyan", width=6)
                _pt.add_column("Service", width=14)
                _pt.add_column("State", width=8)
                _pt.add_column("Banner", style="dim")
                _pt.add_column("Issues", style="bold red")
                for _p in open_ports:
                    _issues = "; ".join(_p.get("service_vulns", []))
                    _pt.add_row(
                        str(_p["port"]), _p.get("service", ""),
                        f"[green]{_p['state'].upper()}[/green]",
                        (_p.get("banner") or "")[:60],
                        _issues or "[green]OK[/green]",
                    )
                console.print(_pt)
            else:
                console.print("[dim]No open ports found[/dim]")
        else:
            results["ports"]["open_ports"] = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2/4 — SEQUENTIAL: Web Fetch + Directory Fuzz
    # Produces home_response needed by JS analysis, XSS, vuln checks.
    # ═══════════════════════════════════════════════════════════════════════════
    home_response = None
    if "p2" in _ckpt_done:
        _p2_ck = _ckpt_saved.get("p2_data") or {}
        home_response = _p2_ck.get("home_response")
        results["web"].update(_p2_ck.get("results_web") or {})
        console.print(f"\n[bold cyan]━━ Phase 2/4[/bold cyan] — [dim]⏩ loaded from checkpoint[/dim]")
    else:
        console.print(f"\n[bold cyan]━━ Phase 2/4[/bold cyan] — Web analysis (homepage + dir fuzz)")
        print_section("Web Analysis", "🌐")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as _progress:
            _task = _progress.add_task("Fetching homepage...", total=None)
            home_response = webfuzz.fetch_url(base_url, timeout=_timeout, user_agent=_ua)

            if home_response:
                _techs = webfuzz.detect_technologies(home_response)
                results["web"]["technologies"] = _techs
                results["web"]["status_code"]  = home_response["status"]
                results["web"]["links"]        = webfuzz.extract_links(home_response, domain)
                if _techs:
                    console.print(f"[green]✓[/green] Technologies: {', '.join(f'[bold cyan]{t}[/bold cyan]' for t in _techs)}")
                console.print(
                    f"[green]✓[/green] HTTP Status: [bold]{home_response['status']}[/bold]  "
                    f"Size: [dim]{home_response['content_length']:,} bytes[/dim]"
                )
            else:
                console.print(f"[red]✗[/red] Could not reach {base_url}")

            if not skip_dirfuzz:
                _dir_wl = wordlist_dirs or str(Path(__file__).parent / "wordlists" / "directories.txt")
                _dir_wordlist = load_wordlist(_dir_wl)
                _progress.update(_task, description=f"Directory fuzzing ({len(_dir_wordlist)} paths)...")
                _dirs = webfuzz.fuzz_directories(base_url, _dir_wordlist, threads=_threads,
                                                 timeout=_timeout, user_agent=_ua)
                results["web"]["directories"] = _dirs
                _interesting = [d for d in _dirs if d["interesting"]]
                if _interesting:
                    console.print(f"[green]✓[/green] Found [bold]{len(_interesting)}[/bold] interesting paths:")
                    _dt = Table(box=box.SIMPLE, show_header=True)
                    _dt.add_column("Path", style="bold")
                    _dt.add_column("Status", width=8)
                    _dt.add_column("Size", width=10, style="dim")
                    for _d in _interesting[:30]:
                        _ss = "green" if _d["status"] == 200 else "yellow" if _d["status"] in (301, 302, 307, 308) else "red"
                        _dt.add_row(_d["url"].replace(base_url, ""), f"[{_ss}]{_d['status']}[/{_ss}]", f"{_d['size']:,}")
                    console.print(_dt)
            _progress.remove_task(_task)
        _ckpt_mod.save(
            _ckpt_path, _ckpt_saved, phase="p2",
            data={"home_response": home_response, "results_web": results["web"]},
            domain=domain, base_url=base_url,
        )
        _ckpt_saved = _ckpt_mod.load(_ckpt_path)

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3/4 — PARALLEL: Crawler + Subdomain Takeover
    # Both independent of each other; crawler produces crawl_results for Phase 4.
    # ═══════════════════════════════════════════════════════════════════════════
    _p3_fns: dict = {}
    crawl_results: dict = {}

    if not skip_crawl:
        def _do_crawl(_threads=_threads, _crawl_delay=crawl_delay):
            return crawler.crawl(
                base_url, max_depth=crawl_depth, max_pages=crawl_pages,
                threads=_threads, timeout=_timeout, user_agent=_ua,
                delay_ms=_crawl_delay, respect_robots=not no_robots,
                allow_subdomains=(crawl_scope == "subdomains"),
            )
        _p3_fns["crawl"] = _do_crawl

    subdomain_list = results.get("recon", {}).get("subdomains", [])
    if not skip_takeover and not skip_subdomains and subdomain_list:
        def _do_takeover(_threads=_threads):
            return takeover.scan_subdomains_for_takeover(subdomain_list, threads=_threads, timeout=_timeout)
        _p3_fns["takeover"] = _do_takeover

    _p3_data: dict = {}
    if "p3" in _ckpt_done:
        _p3_data = _ckpt_saved.get("p3_data") or {}
        console.print(f"\n[bold cyan]━━ Phase 3/4[/bold cyan] — [dim]⏩ loaded from checkpoint[/dim]")
    elif _p3_fns:
        _n_p3 = len(_p3_fns)
        console.print(
            f"\n[bold cyan]━━ Phase 3/4[/bold cyan] — Parallel: "
            + ", ".join(k.upper() for k in _p3_fns)
        )
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console, transient=True) as _prog:
            _pt3 = _prog.add_task("Phase 3…", total=_n_p3)
            with ThreadPoolExecutor(max_workers=_n_p3) as _pool:
                _p3_futs = {name: _pool.submit(fn) for name, fn in _p3_fns.items()}
                for _ in _as_completed(_p3_futs.values()):
                    _prog.advance(_pt3)
        for _name, _fut in _p3_futs.items():
            try:
                _p3_data[_name] = _fut.result()
            except Exception as _e:
                _p3_data[_name] = None
                if not quiet:
                    console.print(f"[red]  ✗ Phase-3 {_name}: {_e}[/red]")
        _ckpt_mod.save(_ckpt_path, _ckpt_saved, phase="p3", data=_p3_data, domain=domain, base_url=base_url)
        _ckpt_saved = _ckpt_mod.load(_ckpt_path)

    # ── Display Crawler ────────────────────────────────────────────────────────
    if not skip_crawl:
        _allow_subs  = (crawl_scope == "subdomains")
        _scope_lbl   = "domain + subdomains" if _allow_subs else "same domain only"
        _robots_lbl  = "[dim](ignoring robots.txt)[/dim]" if no_robots else "[dim](respecting robots.txt)[/dim]"
        _delay_lbl   = f"[dim]{crawl_delay}ms delay/host[/dim]" if crawl_delay else ""
        print_section("Passive Link Crawler", "🕷")
        console.print(
            f"[dim]Scope: {_scope_lbl} | depth {crawl_depth} | max {crawl_pages} pages[/dim] "
            f"{_robots_lbl} {_delay_lbl}"
        )
        crawl_results = _p3_data.get("crawl") or {}
        results["crawl"] = crawl_results
        _cs = crawl_results.get("summary", {})
        _ri = crawl_results.get("robots_txt", {})
        if _ri.get("found") and not no_robots:
            console.print(
                f"  [dim]robots.txt:[/dim] [bold]{len(_ri.get('disallowed', []))}[/bold] disallowed paths, "
                f"[bold]{len(_ri.get('sitemaps', []))}[/bold] sitemap(s)"
            )
            if _ri.get("sitemaps") and not quiet:
                for _sm in _ri["sitemaps"]:
                    console.print(f"    [cyan]Sitemap:[/cyan] {_sm}")
        if _cs.get("blocked_by_robots"):
            console.print(f"  [dim]Skipped {_cs['blocked_by_robots']} URL(s) blocked by robots.txt[/dim]")
        console.print(
            f"[green]✓[/green] Crawled [bold]{_cs.get('pages_crawled', 0)}[/bold] pages — "
            f"[bold cyan]{_cs.get('urls_found', 0)} URLs[/bold cyan]  "
            f"[bold yellow]{_cs.get('js_files_found', 0)} JS files[/bold yellow]  "
            f"[bold]{_cs.get('forms_found', 0)} forms[/bold]  "
            f"[dim]{_cs.get('params_found', 0)} params[/dim]"
        )
        _cpf = crawler.pages_as_findings(crawl_results)
        results["crawl"]["path_findings"] = _cpf
        if _cpf and not quiet:
            for _f in _cpf[:20]:
                print_finding(_f)
        if not quiet and crawl_results.get("all_params"):
            _pp = ", ".join(crawl_results["all_params"][:20])
            if len(crawl_results["all_params"]) > 20:
                _pp += f" … +{len(crawl_results['all_params']) - 20} more"
            console.print(f"  [dim]Params found: {_pp}[/dim]")

    # ── Display Subdomain Takeover ─────────────────────────────────────────────
    if not skip_takeover and not skip_subdomains and subdomain_list:
        print_section("Subdomain Takeover Detection", "🎯")
        console.print(f"[dim]Checked {len(subdomain_list)} subdomains against 24 service fingerprints[/dim]")
        _takeover_findings = _p3_data.get("takeover") or []
        results["takeover"]["findings"] = _takeover_findings
        if _takeover_findings:
            console.print(f"[bold red]⚠  {len(_takeover_findings)} potential takeover(s) found![/bold red]\n")
            _tot = Table(box=box.SIMPLE, show_header=True)
            _tot.add_column("Subdomain", style="bold")
            _tot.add_column("Service", style="bold cyan", width=16)
            _tot.add_column("Severity", width=10)
            _tot.add_column("CNAME Chain", style="dim")
            for _f in _takeover_findings:
                _sev = _f.get("severity", "HIGH")
                _tot.add_row(
                    _f.get("subdomain", ""), _f.get("service", ""),
                    f"[{SEVERITY_STYLES.get(_sev, '')}]{_sev}[/{SEVERITY_STYLES.get(_sev, '')}]",
                    _f.get("cname_chain", ""),
                )
            console.print(_tot)
            for _f in _takeover_findings:
                print_finding(_f)
        else:
            console.print("[green]✓ No subdomain takeover vulnerabilities detected[/green]")
    elif not skip_takeover and not skip_subdomains:
        results["takeover"]["findings"] = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4/4 — PARALLEL: All remaining vulnerability / analysis modules
    # Vuln checks · JS · CORS · Smuggle · XSS · Redirect · OWASP · 14 adv modules
    # All fire at once; display happens sequentially after all complete.
    # ═══════════════════════════════════════════════════════════════════════════
    _p4_fns: dict = {}

    if not skip_vulns:
        def _vuln_checks(_home=home_response, _base=base_url, _to=_timeout):
            _chk = [
                ("header_issues",        lambda: vulns.check_security_headers(_home, _base) if _home else []),
                ("cors_issues",          lambda: vulns.check_cors(_base, _to)),
                ("open_redirect_issues", lambda: vulns.check_open_redirect(_base, _to)),
                ("xss_issues",           lambda: vulns.check_xss(_base, _to)),
                ("sqli_issues",          lambda: vulns.check_sqli(_base, _to)),
                ("lfi_issues",           lambda: vulns.check_lfi(_base, _to)),
                ("sensitive_files",      lambda: vulns.check_sensitive_files(_base, _to)),
                ("http_method_issues",   lambda: vulns.check_http_methods(_base, _to)),
            ]
            _all = []
            with ThreadPoolExecutor(max_workers=8) as _p:
                _vfuts = {_p.submit(_fn): _key for _key, _fn in _chk}
                for _vf in _as_completed(_vfuts):
                    _key = _vfuts[_vf]
                    try:
                        _res = _vf.result()
                    except Exception:
                        _res = []
                    results["vulns"][_key] = _res
                    _all.extend(_res)
            return _all
        _p4_fns["vulns"] = _vuln_checks

    if not skip_js and home_response:
        def _js_analysis():
            _dd = results.get("web", {}).get("directories", [])
            _cj = [{"url": u, "status": 200, "interesting": True} for u in crawl_results.get("all_js_files", [])]
            return jsanalyzer.analyze_js_files(
                base_url, home_response, _dd + _cj,
                threads=_threads, timeout=_timeout, user_agent=_ua
            )
        _p4_fns["js"] = _js_analysis

    if not skip_cors_deep:
        _p4_fns["cors"] = lambda: cors.scan_cors(
            base_url, extra_urls=crawl_results.get("all_urls", []),
            threads=_threads, timeout=_timeout, user_agent=_ua,
        )

    if not skip_smuggle:
        _p4_fns["smuggle"] = lambda: smuggler.scan_smuggling(
            base_url, extra_urls=crawl_results.get("all_urls", []),
            timeout=_timeout + 5, user_agent=_ua,
        )

    if not skip_xss_gen and home_response:
        _p4_fns["xss"] = lambda: xss_gen.scan_xss_contexts(
            base_url, threads=_threads, timeout=_timeout, user_agent=_ua,
            extra_params=crawl_results.get("all_params", []),
            extra_urls=crawl_results.get("all_urls", [])[:30],
        )

    if not skip_redirect:
        _p4_fns["redirect"] = lambda: redirect.scan_redirects(
            base_url, extra_urls=crawl_results.get("all_urls", []),
            threads=_threads, timeout=_timeout, user_agent=_ua, ssl_verify=_ssl_verify,
        )

    if not skip_owasp:
        _p4_fns["owasp"] = lambda: owasp.run_owasp_top10(base_url, timeout=_timeout)

    # ── Crawled-endpoint injection scanner ─────────────────────────────────────
    # Tests XSS / SQLi / open-redirect / LFI / CORS against every real URL and
    # form the crawler discovered — real params at real endpoints, not just the
    # homepage with guessed param names.
    _ep_urls  = crawl_results.get("all_urls",  [])
    _ep_forms = crawl_results.get("all_forms", [])
    if (_ep_urls or _ep_forms) and not skip_vulns:
        def _run_endpoint_scan(
            _eu=_ep_urls, _ef=_ep_forms, _b=base_url, _to=_timeout, _th=_threads
        ):
            return endpoint_scanner.scan_crawled_endpoints(
                _b, _eu, _ef, timeout=_to, threads=min(_th * 2, 40)
            )
        _p4_fns["endpoint_scan"] = _run_endpoint_scan

    _ADV_META = [
        ("sqli",           sqli,           skip_sqli),
        ("auth",           auth,           skip_auth),
        ("pathtraversal",  pathtraversal,  skip_pathtraversal),
        ("cmdinject",      cmdinject,      skip_cmdinject),
        ("bizlogic",       bizlogic,       skip_bizlogic),
        ("infodisclosure", infodisclosure, skip_infodisclosure),
        ("accesscontrol",  accesscontrol,  skip_accesscontrol),
        ("fileupload",     fileupload,     skip_fileupload),
        ("raceconditions", raceconditions, skip_raceconditions),
        ("ssrf",           ssrf,           skip_ssrf),
        ("xxe",            xxe,            skip_xxe),
        ("nosqli",         nosqli,         skip_nosqli),
        ("apitest",        apitest,        skip_apitest),
        ("webcache",       webcache,       skip_webcache),
    ]
    for _akey, _amod, _askip in _ADV_META:
        if not _askip:
            def _make_adv(_m, _b=base_url, _d=domain, _to=_timeout, _th=_threads):
                def _fn():
                    try:
                        return _m.run(_b, domain=_d, timeout=_to, threads=_th)
                    except Exception as _e:
                        return {"findings": [], "error": str(_e)}
                return _fn
            _p4_fns[f"adv_{_akey}"] = _make_adv(_amod)

    _p4_data: dict = {}
    _n_p4 = len(_p4_fns)
    if "p4" in _ckpt_done:
        _p4_data = _ckpt_saved.get("p4_data") or {}
        console.print(f"\n[bold cyan]━━ Phase 4/4[/bold cyan] — [dim]⏩ loaded from checkpoint[/dim]")
    elif _p4_fns:
        console.print(
            f"\n[bold cyan]━━ Phase 4/4[/bold cyan] — Parallel vulnerability scan "
            f"([bold]{_n_p4}[/bold] modules: "
            + ", ".join(k for k in _p4_fns) + ")"
        )
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console, transient=True) as _prog:
            _pt4 = _prog.add_task("Scanning…", total=_n_p4)
            with ThreadPoolExecutor(max_workers=_n_p4) as _pool:
                _p4_futs = {name: _pool.submit(fn) for name, fn in _p4_fns.items()}
                for _ in _as_completed(_p4_futs.values()):
                    _prog.advance(_pt4)
        for _name, _fut in _p4_futs.items():
            try:
                _p4_data[_name] = _fut.result()
            except Exception as _e:
                _p4_data[_name] = {"findings": [], "error": str(_e)}
                if not quiet:
                    console.print(f"[red]  ✗ Phase-4 {_name}: {_e}[/red]")
        _ckpt_mod.save(_ckpt_path, _ckpt_saved, phase="p4", data=_p4_data, domain=domain, base_url=base_url)
        _ckpt_mod.clear(_ckpt_path)

    # ── Display Vulnerability Assessment ──────────────────────────────────────
    if not skip_vulns:
        print_section("Vulnerability Assessment", "🚨")
        _all_v = _p4_data.get("vulns") or []
        _all_v.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 99))
        if _all_v:
            _vc: dict = {}
            for _f in _all_v:
                _s = _f.get("severity", "INFO")
                _vc[_s] = _vc.get(_s, 0) + 1
            _sp = []
            for _s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if _vc.get(_s, 0):
                    _sp.append(f"[{SEVERITY_STYLES[_s]}]{_vc[_s]} {_s}[/{SEVERITY_STYLES[_s]}]")
            console.print("  " + "  ".join(_sp))
            for _finding in _all_v:
                print_finding(_finding)
        else:
            console.print("[green]✓ No vulnerabilities detected[/green]")

    # ── Display Crawled-Endpoint Scan ──────────────────────────────────────────
    _ep_findings = _p4_data.get("endpoint_scan") or []
    if _ep_findings:
        print_section("Crawled Endpoint Scan", "🎯")
        _ep_urls_tested = crawl_results.get("all_urls", [])
        _ep_forms_tested = crawl_results.get("all_forms", [])
        console.print(
            f"[dim]Injected XSS / SQLi / redirect / LFI / CORS payloads into "
            f"{len([u for u in _ep_urls_tested if urllib.parse.urlparse(u).query])} URL(s) "
            f"with real params + {len(_ep_forms_tested)} form(s)[/dim]"
        )
        _ep_findings.sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                x.get("severity", "INFO"), 99
            )
        )
        _ep_vc: dict = {}
        for _f in _ep_findings:
            _s = _f.get("severity", "INFO")
            _ep_vc[_s] = _ep_vc.get(_s, 0) + 1
        _ep_sp = []
        for _s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if _ep_vc.get(_s, 0):
                _ep_sp.append(f"[{SEVERITY_STYLES[_s]}]{_ep_vc[_s]} {_s}[/{SEVERITY_STYLES[_s]}]")
        if _ep_sp:
            console.print("  " + "  ".join(_ep_sp))
        for _ef in _ep_findings:
            print_finding(_ef)
        results.setdefault("vulns", {})["endpoint_scan"] = _ep_findings
    elif "endpoint_scan" in _p4_data:
        print_section("Crawled Endpoint Scan", "🎯")
        _ep_urls_tested = crawl_results.get("all_urls", [])
        _ep_forms_tested = crawl_results.get("all_forms", [])
        console.print(
            f"[dim]Injected payloads into "
            f"{len([u for u in _ep_urls_tested if urllib.parse.urlparse(u).query])} URL(s) "
            f"+ {len(_ep_forms_tested)} form(s)[/dim]"
        )
        console.print("[green]✓ No injection vulnerabilities found in crawled endpoints[/green]")

    # ── Display JavaScript Analysis ────────────────────────────────────────────
    if not skip_js and home_response:
        print_section("JavaScript File Analysis", "📜")
        _ncj = len(crawl_results.get("all_js_files", []))
        console.print(
            f"[dim]Collected JS files from page + directory scan"
            + (f" + {_ncj} crawled" if _ncj else "") + "[/dim]"
        )
        js_results = _p4_data.get("js") or {}
        results["js"] = js_results
        _jssum = js_results.get("summary", {})
        _jsn   = _jssum.get("files_scanned", 0)
        if _jsn == 0:
            console.print("[dim]No JavaScript files found[/dim]")
        else:
            console.print(
                f"[green]✓[/green] Scanned [bold]{_jsn}[/bold] JS file(s) — "
                f"[bold red]{_jssum.get('total_secrets', 0)} secret(s)[/bold red]  "
                f"[bold orange1]{_jssum.get('total_sinks', 0)} sink(s)[/bold orange1]  "
                f"[bold yellow]{_jssum.get('total_endpoints', 0)} endpoint(s)[/bold yellow]  "
                f"[dim]{_jssum.get('total_source_maps', 0)} source map(s)[/dim]"
            )
            if not quiet:
                for _js in js_results.get("files_scanned", []):
                    _ni = len(_js["secrets"]) + len(_js["sinks"]) + len(_js["source_maps"])
                    if _ni:
                        console.print(f"  [bold]{_js['url'].split('/')[-1][:50]}[/bold] — {_ni} issue(s)")
            for _s in js_results.get("all_secrets", []):
                console.print(
                    f"  [{SEVERITY_STYLES.get(_s['severity'], '')}][{_s['severity']}][/{SEVERITY_STYLES.get(_s['severity'], '')}] "
                    f"[bold]{_s['type']}[/bold] in [dim]{_s['js_file'].split('/')[-1]}[/dim] line {_s['line']} "
                    f"— [red]{_s['value_redacted']}[/red]"
                )
            for _sk in js_results.get("all_sinks", []):
                console.print(
                    f"  [{SEVERITY_STYLES.get(_sk['severity'], '')}][{_sk['severity']}][/{SEVERITY_STYLES.get(_sk['severity'], '')}] "
                    f"[bold]{_sk['type']}[/bold] in [dim]{_sk['js_file'].split('/')[-1]}[/dim] line {_sk['line']}"
                )
            if js_results.get("all_source_maps"):
                console.print("[yellow]Source maps found:[/yellow]")
                for _sm in js_results["all_source_maps"]:
                    console.print(f"    [dim]{_sm['map_url']}[/dim]")
            if js_results.get("all_endpoints") and not quiet:
                console.print(f"  [bold]Endpoints discovered ({len(js_results['all_endpoints'])}):[/bold]")
                for _ep in js_results["all_endpoints"][:15]:
                    console.print(f"    [cyan]{_ep['endpoint']}[/cyan] [dim](line {_ep['line']})[/dim]")
        js_findings = jsanalyzer.as_findings(js_results)
        results["js"]["converted_findings"] = js_findings

    # ── Display Deep CORS ──────────────────────────────────────────────────────
    if not skip_cors_deep:
        print_section("Deep CORS Analysis", "🌐")
        _curl = crawl_results.get("all_urls", [])
        console.print(
            f"[dim]Tested 10 bypass techniques across homepage"
            + (f" + {min(19, len(_curl))} crawled URLs" if _curl else "") + "[/dim]"
        )
        cors_results = _p4_data.get("cors") or {}
        results["cors_deep"] = cors_results
        _csum = cors_results.get("summary", {})
        _cfind = cors_results.get("findings", [])
        if not _cfind:
            console.print("[green]✓ No CORS misconfigurations found[/green]")
        else:
            console.print(
                f"[bold red]✗[/bold red] [bold]{len(_cfind)}[/bold] CORS issue(s) — "
                f"[bold red]{_csum.get('critical', 0)} CRITICAL[/bold red]  "
                f"[bold orange1]{_csum.get('high', 0)} HIGH[/bold orange1]  "
                f"[dim]{_csum.get('with_creds', 0)} with credentials[/dim]"
            )
            for _f in _cfind:
                _sev = _f.get("severity", "HIGH")
                _style = SEVERITY_STYLES.get(_sev, "")
                _creds = " [bold red]+ credentials=true[/bold red]" if _f.get("with_credentials") else ""
                console.print(
                    f"  [{_style}][{_sev}][/{_style}] [bold]{_f['label']}[/bold]{_creds}"
                    f"\n    sent: [cyan]{_f['origin_sent']}[/cyan]  →  ACAO: [yellow]{_f['acao']}[/yellow]"
                    f"\n    [dim]{_f['url']}[/dim]"
                )
        _pf = cors_results.get("preflight")
        if _pf and not quiet:
            console.print(
                f"  [dim]OPTIONS preflight:[/dim] ACAO={_pf.get('acao','—')}  "
                f"methods={_pf.get('acam','—')}  headers={_pf.get('acah','—')}"
            )
        results["cors_deep"]["converted_findings"] = cors.as_findings(cors_results)

    # ── Display HTTP Smuggling ─────────────────────────────────────────────────
    if not skip_smuggle:
        print_section("HTTP Request Smuggling", "💉")
        console.print("[dim]Tested CL.TE, TE.CL, TE.TE (6 obfuscation variants) via raw sockets[/dim]")
        smuggle_results = _p4_data.get("smuggle") or {}
        results["smuggle"] = smuggle_results
        _smf = smuggle_results.get("findings", [])
        _sms = smuggle_results.get("summary", {})
        if not _smf:
            console.print(
                f"[green]✓ No smuggling desync detected[/green]  "
                f"[dim]({_sms.get('probes_sent', 0)} probes across "
                f"{len(smuggle_results.get('urls_tested', []))} URL(s), "
                f"baseline {smuggle_results.get('baseline', 0):.1f}s)[/dim]"
            )
        else:
            console.print(f"[bold red]✗ {len(_smf)} desync variant(s) detected![/bold red]")
            for _f in _smf:
                _sev = _f.get("severity", "HIGH")
                console.print(
                    f"  [{SEVERITY_STYLES.get(_sev, '')}][{_sev}][/{SEVERITY_STYLES.get(_sev, '')}] "
                    f"[bold]{_f['variant']}[/bold]  [dim]{', '.join(_f.get('evidence', []))}[/dim]"
                )
        results["smuggle"]["converted_findings"] = smuggler.as_findings(smuggle_results)

    # ── Display Context-Aware XSS ──────────────────────────────────────────────
    if not skip_xss_gen and home_response:
        print_section("Context-Aware XSS Analysis", "🧬")
        _xph = f" + {len(crawl_results['all_params'])} crawled params" if crawl_results.get("all_params") else ""
        console.print(f"[dim]Probed parameters for reflection{_xph}, then crafted context-specific payloads[/dim]")
        xss_findings = _p4_data.get("xss") or []
        results["xss"]["findings"] = xss_findings
        if xss_findings:
            _xconf = [_f for _f in xss_findings if _f.get("confirmed_xss")]
            console.print(
                f"[green]✓[/green] Found [bold]{len(xss_findings)}[/bold] reflection point(s) — "
                f"[{'bold red' if _xconf else 'bold yellow'}]{len(_xconf)} confirmed unencoded"
                f"[/{'bold red' if _xconf else 'bold yellow'}]"
            )
            _xt = Table(box=box.SIMPLE, show_header=True)
            _xt.add_column("Param", style="bold", width=16)
            _xt.add_column("Context", style="cyan")
            _xt.add_column("Severity", width=10)
            _xt.add_column("Confirmed", width=10)
            _xt.add_column("Working Payloads", width=10)
            for _f in xss_findings:
                _sev = _f.get("severity", "HIGH")
                _xt.add_row(
                    f"?{_f.get('param','')}=", _f.get("context_label", ""),
                    f"[{SEVERITY_STYLES.get(_sev, '')}]{_sev}[/{SEVERITY_STYLES.get(_sev, '')}]",
                    "[bold green]YES[/bold green]" if _f.get("confirmed_xss") else "[dim]—[/dim]",
                    str(sum(1 for _p in _f.get("payloads", []) if _p.get("reflected_unencoded"))),
                )
            console.print(_xt)
            for _f in xss_findings:
                if _f.get("confirmed_xss"):
                    console.print(f"\n  [bold red][XSS CONFIRMED][/bold red] ?{_f['param']}= → {_f['context_label']}")
                    console.print(f"  [dim]URL: {_f['url']}[/dim]")
                    console.print(f"  [green]Fix: {_f['recommendation']}[/green]")
                    _wp = [_p["payload"] for _p in _f.get("payloads", []) if _p.get("reflected_unencoded")]
                    if _wp:
                        console.print("  [bold]Payloads that work:[/bold]")
                        for _p in _wp[:4]:
                            console.print(f"    [red]{_p}[/red]")
                    if _f.get("waf_bypass_payloads"):
                        console.print("  [bold]WAF bypasses:[/bold]")
                        for _bp in _f["waf_bypass_payloads"][:3]:
                            console.print(f"    [orange1]{_bp}[/orange1]")
        else:
            console.print("[green]✓ No reflected parameters found[/green]")

    # ── Display Open Redirect ──────────────────────────────────────────────────
    if not skip_redirect:
        print_section("Open Redirect Chain Analysis", "↪")
        redir_results = _p4_data.get("redirect") or {}
        results["redirect"] = redir_results
        _rrurl = crawl_results.get("all_urls", [])
        console.print(
            f"[dim]Tested 50 redirect params × 15 bypass payloads across "
            f"homepage{f' + {min(25, len(_rrurl))} crawled URLs' if _rrurl else ''}[/dim]"
        )
        _rrf = redir_results.get("findings", [])
        _rrs = redir_results.get("summary", {})
        if not _rrf:
            console.print(
                f"[green]✓ No open redirects found[/green]  "
                f"[dim]({_rrs.get('probes_sent', 0):,} probes, "
                f"{len(redir_results.get('urls_tested', []))} URLs)[/dim]"
            )
        else:
            console.print(
                f"[bold red]✗ {len(_rrf)} open redirect(s) found![/bold red]  "
                + (f"[bold red]{_rrs.get('critical', 0)} CRITICAL[/bold red]  " if _rrs.get("critical") else "")
                + (f"[bold magenta]{_rrs.get('oauth_leaks', 0)} OAuth leak(s)[/bold magenta]  " if _rrs.get("oauth_leaks") else "")
                + (f"[bold yellow]{_rrs.get('multi_hop', 0)} multi-hop[/bold yellow]" if _rrs.get("multi_hop") else "")
            )
            for _f in _rrf[:10]:
                _sev = _f.get("severity", "HIGH")
                _hops = " → ".join(
                    f"{_h.get('status','?')} [{'EXT' if _h.get('external') else 'int'}]"
                    for _h in _f.get("chain", [])
                )
                console.print(
                    f"  [{SEVERITY_STYLES.get(_sev, '')}][{_sev}][/{SEVERITY_STYLES.get(_sev, '')}] "
                    f"[bold]{_f['type']}[/bold]  [cyan]?{_f['parameter']}=[/cyan][yellow]{_f['payload_label']}[/yellow]\n"
                    f"    chain: [dim]{_hops}[/dim]\n    [dim]{_f['url']}[/dim]"
                )
        results["redirect"]["converted_findings"] = redirect.as_findings(redir_results)

    # ── Display OWASP Top 10 ───────────────────────────────────────────────────
    if not skip_owasp:
        print_section("OWASP Top 10 (2021) Scan", "🔟")
        owasp_results = _p4_data.get("owasp") or {}
        results["owasp"] = owasp_results
        _os = owasp_results.get("summary", {})
        _ot = _os.get("total", 0)
        if not _ot:
            console.print("[green]✓ No OWASP Top 10 issues detected[/green]")
        else:
            console.print(
                f"[bold red]✗[/bold red] [bold]{_ot}[/bold] OWASP issue(s)  "
                f"[bold red]{_os.get('critical', 0)} CRITICAL[/bold red]  "
                f"[bold orange1]{_os.get('high', 0)} HIGH[/bold orange1]  "
                f"[bold yellow]{_os.get('medium', 0)} MEDIUM[/bold yellow]  "
                f"[dim]{_os.get('low', 0)} LOW[/dim]"
            )
        for _okey, _olabel in [
            ("a01_broken_access_control",    "A01 Broken Access Control"),
            ("a02_cryptographic_failures",    "A02 Cryptographic Failures"),
            ("a05_security_misconfiguration", "A05 Security Misconfiguration"),
            ("a06_outdated_components",       "A06 Outdated Components"),
            ("a07_auth_failures",             "A07 Auth Failures"),
            ("a08_integrity_failures",        "A08 Integrity Failures"),
            ("a09_logging_failures",          "A09 Logging Failures"),
            ("a10_ssrf",                      "A10 SSRF"),
        ]:
            _osf = owasp_results.get(_okey, [])
            if _osf:
                console.print(f"\n  [bold cyan]{_olabel}[/bold cyan] ({len(_osf)} finding(s))")
                for _f in _osf:
                    _sev = _f.get("severity", "INFO")
                    console.print(f"    [{SEVERITY_STYLES.get(_sev, '')}][{_sev}][/{SEVERITY_STYLES.get(_sev, '')}] {_f.get('description', '')}")
                    if _f.get("url") and not quiet:
                        console.print(f"           [dim]↳ {_f['url']}[/dim]")
                    if _f.get("recommendation") and not quiet:
                        console.print(f"           [green]✓ {_f['recommendation']}[/green]")

    # ── Display Advanced Attack Modules ───────────────────────────────────────
    _ADV_LABELS = {
        "sqli":           ("SQL Injection",           "💉"),
        "auth":           ("Authentication Testing",  "🔑"),
        "pathtraversal":  ("Path Traversal",          "📂"),
        "cmdinject":      ("Command Injection",       "⚡"),
        "bizlogic":       ("Business Logic",          "🧠"),
        "infodisclosure": ("Information Disclosure",  "🔍"),
        "accesscontrol":  ("Access Control / IDOR",   "🚪"),
        "fileupload":     ("File Upload",             "📎"),
        "raceconditions": ("Race Conditions",         "🏎"),
        "ssrf":           ("SSRF",                    "🌀"),
        "xxe":            ("XXE Injection",           "📄"),
        "nosqli":         ("NoSQL Injection",         "🍃"),
        "apitest":        ("API Testing",             "🔌"),
        "webcache":       ("Web Cache Deception",     "📦"),
    }
    for _akey, _amod, _askip in _ADV_META:
        if _askip:
            continue
        _alabel, _aemoji = _ADV_LABELS[_akey]
        print_section(_alabel, _aemoji)
        _ar = _p4_data.get(f"adv_{_akey}") or {"findings": []}
        results[_akey] = _ar
        _afl = _ar.get("findings", [])
        if not _afl:
            console.print("[green]✓ No issues detected[/green]")
        else:
            for _f in _afl:
                _sev = _f.get("severity", "INFO")
                console.print(f"  [{SEVERITY_STYLES.get(_sev, '')}][{_sev}][/{SEVERITY_STYLES.get(_sev, '')}] [bold]{_f.get('type','')}[/bold]")
                if _f.get("description") and not quiet:
                    console.print(f"    [dim]{_f['description'][:120]}[/dim]")
                if _f.get("url") and not quiet:
                    console.print(f"    [dim]↳ {_f['url']}[/dim]")
                if _f.get("recommendation") and not quiet:
                    console.print(f"    [green]✓ {_f['recommendation'][:100]}[/green]")

    # ── SUMMARY & REPORT ─────────────────────────────────────────────────────
    elapsed = time.time() - scan_start
    results["scan_duration_seconds"] = round(elapsed, 2)

    print_section("Scan Complete", "✅")
    console.print(f"[dim]Duration: {elapsed:.1f}s[/dim]")

    all_findings_flat = []
    for key in ["header_issues", "cors_issues", "open_redirect_issues", "xss_issues",
                "sqli_issues", "lfi_issues", "sensitive_files", "http_method_issues"]:
        all_findings_flat.extend(results.get("vulns", {}).get(key, []))
    all_findings_flat.extend(results.get("takeover", {}).get("findings", []))
    all_findings_flat.extend(results.get("xss", {}).get("findings", []))
    all_findings_flat.extend(results.get("js", {}).get("converted_findings", []))
    all_findings_flat.extend(results.get("crawl", {}).get("path_findings", []))
    all_findings_flat.extend(results.get("cors_deep", {}).get("converted_findings", []))
    all_findings_flat.extend(results.get("smuggle", {}).get("converted_findings", []))
    all_findings_flat.extend(results.get("redirect", {}).get("converted_findings", []))
    all_findings_flat.extend(results.get("owasp", {}).get("summary", {}).get("all_findings", []))
    for _adv_key in ["sqli", "auth", "pathtraversal", "cmdinject", "bizlogic",
                     "infodisclosure", "accesscontrol", "fileupload", "raceconditions",
                     "ssrf", "xxe", "nosqli", "apitest", "webcache"]:
        all_findings_flat.extend(results.get(_adv_key, {}).get("findings", []))

    # ── SCOPE FILTER ──────────────────────────────────────────────────────────
    if scope_file:
        try:
            from data import scope as _scope_mod
            print_section("Scope Filter", "🎯")
            scope_data = _scope_mod.load_scope(scope_file)
            prog_name  = scope_data.get("program") or scope_file
            console.print(f"[dim]Program: {prog_name}[/dim]")
            console.print(
                f"[dim]In-scope patterns : {len(scope_data['in_scope'])}  |  "
                f"Out-of-scope patterns: {len(scope_data['out_of_scope'])}[/dim]"
            )
            _excluded = _scope_mod.filter_results(results, scope_data)
            results["scope_excluded"] = _excluded
            results["scope_data"]     = scope_data
            all_findings_flat = [f for f in all_findings_flat if f not in _excluded]

            if _excluded and not quiet:
                from rich.table import Table as _STable
                from rich import box as _sbox
                _stbl = _STable(box=_sbox.SIMPLE, show_header=True)
                _stbl.add_column("Type",     style="dim")
                _stbl.add_column("Severity", justify="right")
                _stbl.add_column("Asset",    style="dim")
                _stbl.add_column("Reason",   style="dim italic")
                for _f in _excluded[:30]:
                    _stbl.add_row(
                        _f.get("type", "?")[:40],
                        _f.get("severity", "?"),
                        (_f.get("url") or "")[:60],
                        _f.get("out_of_scope_reason", "")[:50],
                    )
                console.print(_stbl)
                if len(_excluded) > 30:
                    console.print(f"[dim]  … and {len(_excluded) - 30} more excluded findings[/dim]")

            _oos_sev: dict[str, int] = {}
            for _f in _excluded:
                _s = _f.get("severity", "INFO")
                _oos_sev[_s] = _oos_sev.get(_s, 0) + 1
            console.print(
                f"[yellow]  {len(_excluded)} finding(s) removed[/yellow] — "
                "outside program scope; excluded from all reports."
            )
            if not _excluded:
                console.print("[green]  All findings are within the defined scope.[/green]")
        except FileNotFoundError as _exc:
            console.print(f"[red]Error:[/red] {_exc}")
        except Exception as _exc:
            console.print(f"[red]Scope filter error:[/red] {_exc}")
        console.print()

    counts: dict[str, int] = {}
    for f in all_findings_flat:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    summary_table = Table(box=box.ROUNDED, title="[bold]Results Summary[/bold]")
    summary_table.add_column("Category", style="bold")
    summary_table.add_column("Count", justify="right", style="bold cyan")
    summary_table.add_row("Critical findings", f"[bold red]{counts.get('CRITICAL', 0)}[/bold red]")
    summary_table.add_row("High findings", f"[bold orange1]{counts.get('HIGH', 0)}[/bold orange1]")
    summary_table.add_row("Medium findings", f"[bold yellow]{counts.get('MEDIUM', 0)}[/bold yellow]")
    summary_table.add_row("Low findings", f"[bold blue]{counts.get('LOW', 0)}[/bold blue]")
    summary_table.add_row("Open ports", str(len(results.get("ports", {}).get("open_ports", []))))
    summary_table.add_row("Subdomains found", str(len(results.get("recon", {}).get("subdomains", []))))
    summary_table.add_row("Takeover candidates", str(len(results.get("takeover", {}).get("findings", []))))
    waf_info = results.get("waf", {})
    waf_name = waf_info.get("primary_waf") or "None detected"
    waf_rl_triggered = waf_info.get("rate_limit", {}).get("triggered", False)
    summary_table.add_row("WAF detected", waf_name)
    summary_table.add_row("Rate-limit triggered", "[bold red]YES[/bold red]" if waf_rl_triggered else "[green]no[/green]")
    sm_sum = results.get("smuggle", {}).get("summary", {})
    if sm_sum:
        sm_label = "[bold red]YES[/bold red]" if sm_sum.get("vulnerable") else "[green]no[/green]"
        summary_table.add_row("HTTP Smuggling", sm_label)
        if sm_sum.get("variants_hit"):
            summary_table.add_row("Smuggle variants", ", ".join(sm_sum["variants_hit"]))
    redir_sum_out = results.get("redirect", {}).get("summary", {})
    if redir_sum_out:
        summary_table.add_row(
            "Open redirects",
            f"[bold red]{redir_sum_out.get('findings_total', 0)}[/bold red]"
        )
        if redir_sum_out.get("oauth_leaks"):
            summary_table.add_row(
                "OAuth token leaks",
                f"[bold red]{redir_sum_out['oauth_leaks']}[/bold red]"
            )
    xss_confirmed = sum(1 for f in results.get("xss", {}).get("findings", []) if f.get("confirmed_xss"))
    xss_total = len(results.get("xss", {}).get("findings", []))
    summary_table.add_row("XSS contexts found", f"{xss_total} ({xss_confirmed} confirmed)")
    cors_sum = results.get("cors_deep", {}).get("summary", {})
    if cors_sum:
        summary_table.add_row("CORS issues", str(cors_sum.get("findings_total", 0)))
        summary_table.add_row("CORS + credentials", str(cors_sum.get("with_creds", 0)))
    crawl_sum = results.get("crawl", {}).get("summary", {})
    summary_table.add_row("Pages crawled", str(crawl_sum.get("pages_crawled", 0)))
    summary_table.add_row("URLs discovered", str(crawl_sum.get("urls_found", 0)))
    summary_table.add_row("Params harvested", str(crawl_sum.get("params_found", 0)))
    js_sum = results.get("js", {}).get("summary", {})
    summary_table.add_row("JS files analyzed", str(js_sum.get("files_scanned", 0)))
    summary_table.add_row("JS secrets found", str(js_sum.get("total_secrets", 0)))
    summary_table.add_row("JS endpoints found", str(js_sum.get("total_endpoints", 0)))
    summary_table.add_row("Interesting paths", str(len([d for d in results.get("web", {}).get("directories", []) if d.get("interesting")])))
    console.print(summary_table)

    # ── VALIDATION ────────────────────────────────────────────────────────────
    if not skip_validate:
        from data import validator as _validator_mod
        print_section("Validating Findings", "🔬")
        if not quiet:
            console.print(
                "[dim]Re-testing each finding with a targeted HTTP request "
                "to filter false positives and capture evidence…[/dim]"
            )
        val_summary = _validator_mod.run(
            results,
            timeout=_timeout,
            ignore_ssl=ignore_ssl,
            quiet=quiet,
        )
        confirmed = val_summary.get("confirmed", 0)
        likely    = val_summary.get("likely", 0)
        rejected  = val_summary.get("rejected", 0)
        total     = val_summary.get("total", 0)
        if not quiet:
            from rich.table import Table as _Table
            from rich import box as _box
            val_tbl = _Table(box=_box.SIMPLE, show_header=True)
            val_tbl.add_column("Outcome",   style="bold")
            val_tbl.add_column("Count",     justify="right")
            val_tbl.add_column("Meaning",   style="dim")
            val_tbl.add_row("[green]✔ Confirmed[/green]", str(confirmed),
                            "Reproduced with concrete HTTP evidence")
            val_tbl.add_row("[yellow]⚠ Likely[/yellow]",    str(likely),
                            "Strong signal; OOB or manual verification needed")
            val_tbl.add_row("[red]✘ Rejected[/red]",    str(rejected),
                            "Could not reproduce — filtered from reports")
            val_tbl.add_row("Total validated", str(total), "")
            console.print(val_tbl)
        if rejected and not quiet:
            console.print(
                f"[red]  {rejected} finding(s) removed[/red] — could not be reproduced "
                "and are [bold]excluded from all reports[/bold]."
            )
        console.print()

    # ── H1 TRIAGE MODE ────────────────────────────────────────────────────────
    if triage_mode:
        _TRIAGE_SEVS = {"CRITICAL", "HIGH"}
        _before = len(all_findings_flat)
        all_findings_flat = [
            f for f in all_findings_flat
            if f.get("severity") in _TRIAGE_SEVS
            and f.get("confidence", "likely") in ("confirmed", "likely")
        ]
        _kept    = len(all_findings_flat)
        _dropped = _before - _kept
        if not quiet:
            console.print(
                Panel(
                    f"[bold green]H1 Triage Mode[/bold green] — showing only "
                    f"[bold red]CRITICAL[/bold red] & [bold orange1]HIGH[/bold orange1] "
                    f"findings with [green]confirmed[/green] or [yellow]likely[/yellow] confidence.\n\n"
                    f"  [bold cyan]{_kept}[/bold cyan] findings kept for submission  "
                    f"[dim]({_dropped} lower-severity / rejected dropped)[/dim]",
                    border_style="green",
                    title="[bold green]🎯 HackerOne Triage[/bold green]",
                )
            )
        results["triage"] = {
            "enabled":   True,
            "kept":      _kept,
            "dropped":   _dropped,
            "severities": list(_TRIAGE_SEVS),
        }
        if not export_h1:
            export_h1 = True
            if not quiet:
                console.print(
                    "[dim]  --export-h1 auto-enabled by triage mode "
                    "— individual submission files will be generated.[/dim]\n"
                )

    report_paths: dict[str, str] = {}
    if not no_report:
        safe_target = domain.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(output_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        json_path = report_dir / f"{safe_target}_{ts}.json"
        reporter.save_json(results, str(json_path))
        console.print(f"\n[green]✓[/green] JSON report: [bold]{json_path}[/bold]")
        report_paths["json"] = str(json_path)

        if not json_only:
            html_path = report_dir / f"{safe_target}_{ts}.html"
            reporter.save_html(results, str(html_path))
            console.print(f"[green]✓[/green] HTML report: [bold]{html_path}[/bold]")
            report_paths["html"] = str(html_path)

        if report_owasp:
            owasp_path = report_dir / f"{safe_target}_{ts}_owasp.html"
            reporter.save_owasp_html(results, str(owasp_path))
            console.print(f"[green]✓[/green] OWASP report: [bold]{owasp_path}[/bold]")
            report_paths["owasp"] = str(owasp_path)

        if export_h1:
            h1_path = report_dir / f"{safe_target}_{ts}_hackerone.md"
            h1_result = reporter.save_hackerone_md(results, str(h1_path))
            findings_dir = h1_result.get("findings_dir", "")
            h1_count     = h1_result.get("count", 0)
            console.print(f"[green]✓[/green] HackerOne summary: [bold]{h1_path}[/bold]")
            if h1_count:
                console.print(
                    f"[green]✓[/green] {h1_count} individual submission file(s): "
                    f"[bold]{findings_dir}/[/bold]"
                )
            else:
                console.print("[yellow]  No Critical/High/Medium findings — individual files not generated.[/yellow]")
            report_paths["hackerone"] = str(h1_path)
            report_paths["hackerone_findings_dir"] = findings_dir

    console.print()
    return {
        "target":       target,
        "domain":       domain,
        "counts":       counts,
        "duration":     elapsed,
        "report_dir":   output_dir,
        "report_paths": report_paths,
    }


@click.command()
@click.argument("target", required=False, default=None)
@click.option("--target-list", "-T", default=None, type=click.Path(exists=True),
              help="File with one target (domain or URL) per line; full scan runs for each")
@click.option("--config", "-c", default=None, help="Path to config YAML file")
@click.option("--output-dir", "-o", default="reports", help="Output directory for reports")
@click.option("--skip-waf", is_flag=True, help="Skip WAF/rate-limit fingerprinting")
@click.option("--skip-ports", is_flag=True, help="Skip port scanning")
@click.option("--skip-subdomains", is_flag=True, help="Skip subdomain enumeration")
@click.option("--skip-dirfuzz", is_flag=True, help="Skip directory fuzzing")
@click.option("--skip-vulns", is_flag=True, help="Skip vulnerability checks")
@click.option("--skip-takeover", is_flag=True, help="Skip subdomain takeover checks")
@click.option("--skip-xss-gen", is_flag=True, help="Skip context-aware XSS payload generation")
@click.option("--skip-js", is_flag=True, help="Skip JavaScript file analysis")
@click.option("--skip-cors-deep", is_flag=True, help="Skip deep CORS misconfiguration scan")
@click.option("--skip-smuggle", is_flag=True, help="Skip HTTP request smuggling detection")
@click.option("--skip-redirect", is_flag=True, help="Skip open redirect chain analysis")
@click.option("--ignore-ssl", is_flag=True, help="Ignore SSL certificate errors (self-signed, expired, etc.)")
@click.option("--skip-crawl", is_flag=True, help="Skip passive link crawler")
@click.option("--crawl-depth", default=2, show_default=True, help="Max crawl depth (default: 2)")
@click.option("--crawl-pages", default=60, show_default=True, help="Max pages to crawl (default: 60)")
@click.option("--crawl-scope", default="domain", show_default=True,
              type=click.Choice(["domain", "subdomains"]),
              help="Crawl scope: domain = same host only, subdomains = all subdomains of target")
@click.option("--crawl-delay", default=0, show_default=True,
              help="Milliseconds to wait between requests to the same host (0 = no rate limit)")
@click.option("--no-robots", is_flag=True, help="Ignore robots.txt when crawling")
@click.option("--ports", default="common", type=click.Choice(["common", "extended", "all"]),
              help="Port range to scan (default: common)")
@click.option("--threads", "-t", default=None, type=int, help="Number of threads (overrides config)")
@click.option("--timeout", default=None, type=int, help="Request timeout in seconds (overrides config)")
@click.option("--no-report", is_flag=True, help="Do not save reports")
@click.option("--json-only", is_flag=True, help="Only save JSON report")
@click.option("--report-owasp", is_flag=True, help="Generate a dedicated OWASP Top 10 compliance HTML report")
@click.option("--export-h1", is_flag=True, help="Generate a HackerOne-ready markdown report (.md) alongside HTML/JSON")
@click.option("--resume", is_flag=True, help="Skip targets that already have a report in --output-dir (use with --target-list to continue an interrupted scan)")
@click.option("--skip-validate", is_flag=True, help="Skip post-scan finding validation (validation re-tests each finding and removes false positives)")
@click.option("--wordlist-subdomains", default=None, help="Custom subdomain wordlist path")
@click.option("--wordlist-dirs", default=None, help="Custom directory wordlist path")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--skip-owasp", is_flag=True, help="Skip dedicated OWASP Top 10 checks")
@click.option("--skip-sqli", is_flag=True, help="Skip SQL injection module")
@click.option("--skip-auth", is_flag=True, help="Skip authentication testing module")
@click.option("--skip-pathtraversal", is_flag=True, help="Skip path traversal module")
@click.option("--skip-cmdinject", is_flag=True, help="Skip command injection module")
@click.option("--skip-bizlogic", is_flag=True, help="Skip business logic vulnerability module")
@click.option("--skip-infodisclosure", is_flag=True, help="Skip information disclosure module")
@click.option("--skip-accesscontrol", is_flag=True, help="Skip access control / IDOR module")
@click.option("--skip-fileupload", is_flag=True, help="Skip file upload vulnerability module")
@click.option("--skip-raceconditions", is_flag=True, help="Skip race condition module")
@click.option("--skip-ssrf", is_flag=True, help="Skip SSRF module")
@click.option("--skip-xxe", is_flag=True, help="Skip XXE injection module")
@click.option("--skip-nosqli", is_flag=True, help="Skip NoSQL injection module")
@click.option("--skip-apitest", is_flag=True, help="Skip API testing module")
@click.option("--skip-webcache", is_flag=True, help="Skip web cache deception/poisoning module")
@click.option("--scope-file", "-s", default=None, metavar="PATH",
              help="JSON/YAML scope file listing in_scope and out_of_scope patterns. "
                   "Findings outside scope are stripped from all reports. "
                   "See scope_example.json for the format.")
@click.option("--triage", is_flag=True,
              help="H1 triage mode: keep only CRITICAL/HIGH findings that are confirmed or likely. "
                   "Automatically enables --export-h1. Ideal before submitting to HackerOne.")
@click.option("--list-checkpoints", "list_checkpoints", is_flag=True,
              help="List all in-progress scan checkpoints and exit.")
def main(target, target_list, config, output_dir, skip_waf, skip_ports, skip_subdomains, skip_dirfuzz,
         skip_vulns, skip_takeover, skip_xss_gen, skip_js, skip_cors_deep, skip_smuggle,
         skip_redirect, ignore_ssl, skip_crawl, crawl_depth, crawl_pages, crawl_scope,
         crawl_delay, no_robots, ports, threads, timeout, no_report, json_only, report_owasp,
         export_h1, resume, skip_validate, scope_file, triage, list_checkpoints,
         wordlist_subdomains, wordlist_dirs, quiet, skip_owasp,
         skip_sqli, skip_auth, skip_pathtraversal, skip_cmdinject, skip_bizlogic,
         skip_infodisclosure, skip_accesscontrol, skip_fileupload, skip_raceconditions,
         skip_ssrf, skip_xxe, skip_nosqli, skip_apitest, skip_webcache):
    """
    BugBountyTool — Automated recon & vulnerability scanner

    TARGET can be a domain (example.com) or full URL (https://example.com).
    Use --target-list / -T to scan multiple targets from a file (one per line).

    Examples:\n
      python bb.py example.com\n
      python bb.py https://example.com --ports extended\n
      python bb.py example.com --skip-ports --skip-subdomains\n
      python bb.py example.com -o /tmp/reports --threads 30\n
      python bb.py --target-list targets.txt --export-h1
    """
    # ── --list-checkpoints early exit ─────────────────────────────────────────
    if list_checkpoints:
        from data import checkpoint as _ckmod
        from datetime import datetime as _dt
        _entries = _ckmod.list_all(output_dir)
        _PHASES = ["p1", "p2", "p3", "p4"]
        _PHASE_LABELS = {"p1": "Recon", "p2": "Web", "p3": "Crawl", "p4": "Vulns"}
        _now = _dt.now()

        def _age(ts: str) -> str:
            if not ts:
                return "?"
            try:
                delta = _now - _dt.fromisoformat(ts)
                s = int(delta.total_seconds())
                if s < 60:   return f"{s}s ago"
                if s < 3600: return f"{s//60}m ago"
                if s < 86400:return f"{s//3600}h {(s%3600)//60}m ago"
                return f"{s//86400}d ago"
            except Exception:
                return "?"

        console.print()
        console.print(
            Panel(
                f"[bold white]Scans that were interrupted mid-run.[/bold white]  "
                f"Resume any with [bold cyan]python bb.py <domain> --resume[/bold cyan]",
                title=f"[bold red]⏸  Checkpoint Registry[/bold red]  "
                      f"[dim]─[/dim]  [bold]{len(_entries)}[/bold] in-progress scan{'s' if len(_entries) != 1 else ''}",
                border_style="red",
                padding=(0, 2),
            )
        )

        if not _entries:
            console.print(
                "\n  [dim]No checkpoints found in [bold]"
                f"{output_dir}/.checkpoints/[/bold][/dim]\n"
            )
            sys.exit(0)

        _tbl = Table(
            box=box.ROUNDED,
            border_style="bright_black",
            header_style="bold cyan",
            show_lines=True,
            padding=(0, 1),
        )
        _tbl.add_column("#",         style="dim",        width=3,  justify="right")
        _tbl.add_column("Domain",    style="bold white",  min_width=22)
        _tbl.add_column("Phases",    min_width=26)
        _tbl.add_column("Progress",  justify="center",   width=10)
        _tbl.add_column("Last seen", style="dim",         width=14)
        _tbl.add_column("Started",   style="dim",         width=18)

        for _idx, _e in enumerate(_entries, 1):
            _done = set(_e["completed_phases"])
            _n_done = len(_done)
            _total  = len(_PHASES)

            # Phase pills
            _pills = " ".join(
                f"[bold green]● {_PHASE_LABELS[p]}[/bold green]"
                if p in _done
                else f"[bright_black]○ {_PHASE_LABELS[p]}[/bright_black]"
                for p in _PHASES
            )

            # Progress bar (filled blocks)
            _filled = round(_n_done / _total * 8)
            _bar = (
                f"[green]{'█' * _filled}[/green]"
                f"[bright_black]{'░' * (8 - _filled)}[/bright_black]"
                f" [bold]{_n_done}/{_total}[/bold]"
            )

            _tbl.add_row(
                str(_idx),
                _e["domain"],
                _pills,
                _bar,
                _age(_e["updated_at"]),
                _e["created_at"][:16].replace("T", " ") if _e["created_at"] else "?",
            )

        console.print(_tbl)
        console.print()
        console.print(
            "  [bold]Resume a scan:[/bold]  "
            "[cyan]python bb.py[/cyan] [green]<domain>[/green] [yellow]--resume[/yellow]"
        )
        console.print(
            "  [bold]Output dir  :[/bold]  "
            f"[dim]{output_dir}/.checkpoints/[/dim]"
        )
        console.print()
        sys.exit(0)

    cfg = load_config(config)

    targets: list[str] = []
    if target_list:
        with open(target_list) as _fh:
            for _line in _fh:
                _t = _line.strip()
                if _t and not _t.startswith("#"):
                    targets.append(_t)
        if not targets:
            console.print("[red]Error:[/red] --target-list file contains no valid targets.")
            sys.exit(1)
    if target:
        targets.insert(0, target)

    if not targets:
        console.print(
            "[red]Error:[/red] supply a TARGET argument or --target-list file.\n"
            "  Example:  python bb.py example.com\n"
            "  Example:  python bb.py --target-list targets.txt"
        )
        sys.exit(1)

    is_multi = len(targets) > 1
    if is_multi and not quiet:
        _print_big_banner()
        _preview = "\n".join(f"  {i+1}. {t}" for i, t in enumerate(targets[:10]))
        if len(targets) > 10:
            _preview += f"\n  … and {len(targets) - 10} more"
        console.print(Panel(
            f"[bold]Targets:[/bold] {len(targets)}\n{_preview}\n\n"
            f"[bold]Threads:[/bold] {threads or 30}  "
            f"[bold]Timeout:[/bold] {timeout or 4}s  "
            f"[bold]Ports:[/bold] {ports}",
            title=f"[bold cyan]Multi-Target Scan — {len(targets)} Targets[/bold cyan]",
            border_style="cyan",
        ))

    opts = dict(
        output_dir=output_dir, threads=threads, timeout=timeout,
        no_report=no_report, json_only=json_only, report_owasp=report_owasp,
        export_h1=export_h1, skip_validate=skip_validate, scope_file=scope_file,
        triage_mode=triage, quiet=quiet,
        skip_waf=skip_waf, skip_ports=skip_ports, skip_subdomains=skip_subdomains,
        skip_dirfuzz=skip_dirfuzz, skip_vulns=skip_vulns, skip_takeover=skip_takeover,
        skip_xss_gen=skip_xss_gen, skip_js=skip_js, skip_cors_deep=skip_cors_deep,
        skip_smuggle=skip_smuggle, skip_redirect=skip_redirect, ignore_ssl=ignore_ssl,
        skip_crawl=skip_crawl, crawl_depth=crawl_depth, crawl_pages=crawl_pages,
        crawl_scope=crawl_scope, crawl_delay=crawl_delay, no_robots=no_robots,
        ports=ports, wordlist_subdomains=wordlist_subdomains, wordlist_dirs=wordlist_dirs,
        skip_owasp=skip_owasp, skip_sqli=skip_sqli, skip_auth=skip_auth,
        skip_pathtraversal=skip_pathtraversal, skip_cmdinject=skip_cmdinject,
        skip_bizlogic=skip_bizlogic, skip_infodisclosure=skip_infodisclosure,
        skip_accesscontrol=skip_accesscontrol, skip_fileupload=skip_fileupload,
        skip_raceconditions=skip_raceconditions, skip_ssrf=skip_ssrf, skip_xxe=skip_xxe,
        skip_nosqli=skip_nosqli, skip_apitest=skip_apitest, skip_webcache=skip_webcache,
    )

    scan_summaries: list[dict] = []
    for _i, _t in enumerate(targets, 1):
        if is_multi:
            console.print(
                f"\n[bold cyan on black] ❯ Target {_i}/{len(targets)}: {_t} [/bold cyan on black]\n"
            )
        _summary = _run_single_scan(_t, cfg, opts)
        scan_summaries.append(_summary)

    if is_multi:
        print_section(f"Multi-Target Summary — {len(targets)} Targets Scanned", "📊")
        mt_table = Table(box=box.ROUNDED, title=f"[bold]{len(targets)} Targets[/bold]")
        mt_table.add_column("Target",   style="bold")
        mt_table.add_column("Critical", justify="right", style="bold red")
        mt_table.add_column("High",     justify="right", style="bold orange1")
        mt_table.add_column("Medium",   justify="right", style="bold yellow")
        mt_table.add_column("Low",      justify="right", style="bold blue")
        mt_table.add_column("Duration", justify="right", style="dim")
        mt_table.add_column("Reports",  style="dim")
        for _s in scan_summaries:
            _c = _s.get("counts", {})
            _paths_label = ", ".join(
                Path(_p).suffix.lstrip(".").upper()
                for _p in _s.get("report_paths", {}).values()
            )
            mt_table.add_row(
                _s["target"],
                str(_c.get("CRITICAL", 0)),
                str(_c.get("HIGH", 0)),
                str(_c.get("MEDIUM", 0)),
                str(_c.get("LOW", 0)),
                f"{_s.get('duration', 0):.1f}s",
                _paths_label or "—",
            )
        console.print(mt_table)
        console.print()




if __name__ == "__main__":
    main()
