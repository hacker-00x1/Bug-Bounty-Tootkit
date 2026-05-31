#!/usr/bin/python3

"""
Bug Bounty ToolKit — fsociety-style interactive menu launcher.

Run directly:  python toolkit.py
               python toolkit.py -t example.com
"""

import sys
import os
import subprocess
import shutil
import argparse

try:
    from rich.console import Console
    from rich.text import Text
    from rich.rule import Rule
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.table import Table
    from rich import box
except ImportError:
    print("Missing dependency: pip install rich")
    sys.exit(1)

console = Console()

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
BB_PY    = os.path.join(TOOL_DIR, "bb.py")
PYTHON   = sys.executable

# ── Banner ────────────────────────────────────────────────────────────────────

ASCII_ART = """\
[bold red]██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗ ██╗[/bold red]
[bold red]██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚██╗██╔╝███║[/bold red]
[bold red]███████║███████║██║     █████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║ ╚███╔╝  ██║[/bold red]
[bold red]██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ██╔██╗  ██║[/bold red]
[bold red]██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝██╔╝ ██╗ ██║[/bold red]
[dim red]╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝[/dim red]"""

BANNER  = "[bold red]  Hacker00X1[/bold red]  [dim]─  Bug Bounty Tool Kit  |  Recon · Scan · Exploit · Report[/dim]"
TAGLINE = "[bold white]  Bug Bounty Hunter's ToolKit[/bold white]  [dim]| Recon · Scan · Exploit · Report[/dim]"
WARN    = "[dim red]  ⚠  Only scan targets you own or have explicit written permission to test.[/dim red]"


def _print_big_banner():
    console.print()
    panel = Panel(
        ASCII_ART + "\n\n[dim]  Bug Bounty Tool Kit  ─  Recon · Scan · Exploit · Report[/dim]",
        border_style="bold red",
        padding=(0, 2),
        subtitle="[dim red]Only scan targets you own or have explicit written permission to test[/dim red]",
    )
    console.print(panel)

# ── Menu items ─────────────────────────────────────────────────────────────────
#
# Each entry:
#   id       – numeric key the user types
#   label    – display name
#   icon     – emoji icon
#   desc     – one-line description
#   skip_all – if True, skip every module not in keep_flags
#   flags    – extra bb.py flags to ADD (for module-only runs we build skip list)
#   keep     – set of module ids to keep enabled (others skipped)

ALL_SKIP_FLAGS = [
    "--skip-waf", "--skip-subdomains", "--skip-ports", "--skip-dirfuzz",
    "--skip-vulns", "--skip-takeover", "--skip-xss-gen", "--skip-js",
    "--skip-cors-deep", "--skip-smuggle", "--skip-crawl", "--skip-owasp",
    "--skip-sqli", "--skip-auth", "--skip-pathtraversal", "--skip-cmdinject",
    "--skip-bizlogic", "--skip-infodisclosure", "--skip-accesscontrol",
    "--skip-fileupload", "--skip-raceconditions", "--skip-ssrf",
    "--skip-xxe", "--skip-nosqli", "--skip-apitest", "--skip-webcache",
]

RECON_SECTION = [
    {
        "id": "1", "icon": "🛡", "label": "WAF & Rate-Limit Fingerprint",
        "desc": "Identify WAF/CDN, detect rate-limiting, auto-tune aggressiveness",
        "keep": {"waf"},
    },
    {
        "id": "2", "icon": "🔍", "label": "DNS Recon & Subdomain Enum",
        "desc": "DNS records, WHOIS, crt.sh + wordlist subdomain brute-force",
        "keep": {"recon", "subdomains"},
    },
    {
        "id": "3", "icon": "🎯", "label": "Subdomain Takeover Check",
        "desc": "Dangling CNAME detection — 50+ cloud/SaaS service fingerprints",
        "keep": {"recon", "subdomains", "takeover"},
    },
    {
        "id": "4", "icon": "🔌", "label": "Port Scanner",
        "desc": "TCP connect scan with banner grab, service ID & vuln flags",
        "keep": {"ports"},
    },
    {
        "id": "5", "icon": "🕷 ", "label": "Passive Crawler",
        "desc": "Link crawl with robots.txt parsing, rate-limit, scope control",
        "keep": {"crawl"},
    },
]

WEB_SECTION = [
    {
        "id": "6", "icon": "🔒", "label": "Vulnerability Scanner",
        "desc": "Headers, open redirect, XSS, SQLi, LFI, sensitive files, HTTP methods",
        "keep": {"vulns"},
    },
    {
        "id": "7", "icon": "🌀", "label": "Deep CORS Tester",
        "desc": "10 origin-bypass techniques (null, pre/post-domain, HTTP downgrade …)",
        "keep": {"cors"},
    },
    {
        "id": "8", "icon": "🧬", "label": "Context-Aware XSS Generator",
        "desc": "Discovers reflected parameters, generates context-aware payloads",
        "keep": {"xss_gen"},
    },
    {
        "id": "9", "icon": "💉", "label": "HTTP Request Smuggling",
        "desc": "CL.TE / TE.CL / TE.TE desync via raw socket probes",
        "keep": {"smuggle"},
    },
    {
        "id": "10", "icon": "🔎", "label": "JS File Analyzer",
        "desc": "Secrets, DOM sinks, endpoints, source-maps in all JS files",
        "keep": {"js"},
    },
    {
        "id": "11", "icon": "📁", "label": "Directory Fuzzer",
        "desc": "Web path discovery across ~200 common endpoints & files",
        "keep": {"dirfuzz"},
    },
]

ADVANCED_SECTION = [
    {
        "id": "32", "icon": "💉", "label": "SQL Injection",
        "desc": "Error-based, time-based blind & UNION-based SQLi across all URL params",
        "keep": {"sqli"},
    },
    {
        "id": "33", "icon": "🔑", "label": "Authentication Testing",
        "desc": "Default creds, cookie flags, JWT exposure, username enumeration",
        "keep": {"auth"},
    },
    {
        "id": "34", "icon": "📂", "label": "Path Traversal",
        "desc": "LFI/path traversal — /etc/passwd, win.ini, encoded bypasses",
        "keep": {"pathtraversal"},
    },
    {
        "id": "35", "icon": "⚡", "label": "Command Injection",
        "desc": "OS command injection — output-based & time-based blind",
        "keep": {"cmdinject"},
    },
    {
        "id": "36", "icon": "🧠", "label": "Business Logic",
        "desc": "Workflow bypass, privilege escalation, mass assignment, negative values",
        "keep": {"bizlogic"},
    },
    {
        "id": "37", "icon": "🔍", "label": "Information Disclosure",
        "desc": "Exposed .env, git, logs, backups, secrets, stack traces",
        "keep": {"infodisclosure"},
    },
    {
        "id": "38", "icon": "🚪", "label": "Access Control / IDOR",
        "desc": "Unauth admin access, 403 bypass headers, IDOR detection",
        "keep": {"accesscontrol"},
    },
    {
        "id": "39", "icon": "📎", "label": "File Upload Vulnerabilities",
        "desc": "Web shell upload, extension bypass, .htaccess, SVG/HTML XSS uploads",
        "keep": {"fileupload"},
    },
    {
        "id": "40", "icon": "🏎 ", "label": "Race Conditions",
        "desc": "15-thread concurrent requests to coupons, payments, votes",
        "keep": {"raceconditions"},
    },
    {
        "id": "41", "icon": "🌀", "label": "SSRF",
        "desc": "Cloud metadata probing, blind SSRF, URL param injection",
        "keep": {"ssrf"},
    },
    {
        "id": "42", "icon": "📄", "label": "XXE Injection",
        "desc": "Classic, CDATA, PHP filter, parameter entity XXE payloads",
        "keep": {"xxe"},
    },
    {
        "id": "43", "icon": "🍃", "label": "NoSQL Injection",
        "desc": "MongoDB operator injection ($gt, $ne, $regex) via JSON & forms",
        "keep": {"nosqli"},
    },
    {
        "id": "44", "icon": "🔌", "label": "API Testing",
        "desc": "Discovery, GraphQL introspection, rate-limit, JWT none-alg, CORS",
        "keep": {"apitest"},
    },
    {
        "id": "45", "icon": "📦", "label": "Web Cache Deception",
        "desc": "Cache poisoning via headers, unkeyed params, path-based deception",
        "keep": {"webcache"},
    },
]

OWASP_SECTION = [
    {
        "id": "17", "icon": "🔑", "label": "A01 — Broken Access Control",
        "desc": "Admin panels, forced browsing, IDOR parameter surfaces",
        "keep": {"owasp"},
    },
    {
        "id": "18", "icon": "🔐", "label": "A02 — Cryptographic Failures",
        "desc": "HTTP vs HTTPS, TLS version, cert expiry, missing HSTS",
        "keep": {"owasp"},
    },
    {
        "id": "19", "icon": "⚙ ", "label": "A05 — Security Misconfiguration",
        "desc": "Default pages, verbose errors, debug endpoints",
        "keep": {"owasp"},
    },
    {
        "id": "20", "icon": "📦", "label": "A06 — Outdated Components",
        "desc": "Server/framework version disclosure, EOL component detection",
        "keep": {"owasp"},
    },
    {
        "id": "21", "icon": "🧩", "label": "A07 — Auth Failures",
        "desc": "Default credentials, insecure cookie flags, unauthenticated APIs",
        "keep": {"owasp"},
    },
    {
        "id": "22", "icon": "🛡", "label": "A08 — Integrity Failures",
        "desc": "Missing CSP, external scripts without SRI",
        "keep": {"owasp"},
    },
    {
        "id": "23", "icon": "📋", "label": "A09 — Logging Failures",
        "desc": "Exposed log files leaking IPs, paths, and internal errors",
        "keep": {"owasp"},
    },
    {
        "id": "24", "icon": "🌀", "label": "A10 — SSRF",
        "desc": "Cloud metadata endpoints, internal IP probing via URL params",
        "keep": {"owasp"},
    },
    {
        "id": "25", "icon": "🔟", "label": "Full OWASP Top 10 Scan",
        "desc": "All eight automated OWASP A01–A10 checks in one pass",
        "keep": {"owasp"},
    },
]

SCAN_PRESETS = [
    {
        "id": "26", "icon": "⚡", "label": "Quick Scan",
        "desc": "WAF + Vulns + CORS + Smuggling + OWASP  (~2–3 min)",
        "flags": ["--skip-subdomains", "--skip-ports", "--skip-dirfuzz",
                  "--skip-crawl", "--skip-xss-gen", "--skip-js", "--skip-takeover"],
    },
    {
        "id": "27", "icon": "🔍", "label": "Standard Scan",
        "desc": "All modules except subdomain brute-force  (~5–10 min)",
        "flags": ["--skip-subdomains"],
    },
    {
        "id": "28", "icon": "💣", "label": "Full Scan",
        "desc": "Everything enabled, extended port range  (~20+ min)",
        "flags": ["--ports", "extended"],
    },
    {
        "id": "29", "icon": "🌐", "label": "Web-Only Scan",
        "desc": "No port scan, no subdomain enum — pure web analysis",
        "flags": ["--skip-ports", "--skip-subdomains"],
    },
    {
        "id": "30", "icon": "🕵 ", "label": "Recon-Only Scan",
        "desc": "DNS + Subdomain enum + Port scan — no web probes",
        "flags": ["--skip-vulns", "--skip-cors-deep", "--skip-xss-gen",
                  "--skip-js", "--skip-crawl", "--skip-smuggle", "--skip-dirfuzz",
                  "--skip-takeover", "--skip-waf", "--skip-owasp"],
    },
    {
        "id": "31", "icon": "🏅", "label": "OWASP Top 10 Only",
        "desc": "Dedicated OWASP A01–A10 checks, no recon or port scan",
        "flags": ["--skip-ports", "--skip-subdomains", "--skip-dirfuzz",
                  "--skip-waf", "--skip-takeover", "--skip-smuggle",
                  "--skip-crawl", "--skip-js", "--skip-xss-gen",
                  "--skip-cors-deep", "--skip-vulns"],
    },
]

ALL_MODULES_BY_ID = {
    "waf": "--skip-waf", "subdomains": "--skip-subdomains",
    "ports": "--skip-ports", "dirfuzz": "--skip-dirfuzz",
    "vulns": "--skip-vulns", "takeover": "--skip-takeover",
    "xss_gen": "--skip-xss-gen", "js": "--skip-js",
    "cors": "--skip-cors-deep", "smuggle": "--skip-smuggle",
    "crawl": "--skip-crawl", "recon": None, "owasp": "--skip-owasp",
    "sqli": "--skip-sqli", "auth": "--skip-auth",
    "pathtraversal": "--skip-pathtraversal", "cmdinject": "--skip-cmdinject",
    "bizlogic": "--skip-bizlogic", "infodisclosure": "--skip-infodisclosure",
    "accesscontrol": "--skip-accesscontrol", "fileupload": "--skip-fileupload",
    "raceconditions": "--skip-raceconditions", "ssrf": "--skip-ssrf",
    "xxe": "--skip-xxe", "nosqli": "--skip-nosqli",
    "apitest": "--skip-apitest", "webcache": "--skip-webcache",
}


# ── State ──────────────────────────────────────────────────────────────────────

class State:
    def __init__(self):
        self.target     = ""
        self.output_dir = "reports"
        self.threads    = 30
        self.timeout    = 4
        self.ports      = "common"
        self.quiet      = False
        self.json_only  = False


state = State()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _divider(char="═", color="red"):
    width = shutil.get_terminal_size((100, 24)).columns
    console.print(f"[{color}]" + char * width + f"[/{color}]")


def _header():
    _print_big_banner()
    console.print()
    tgt = f"[bold green]{state.target}[/bold green]" if state.target else "[dim]not set[/dim]"
    console.print(
        f"  [dim]target:[/dim] {tgt}   "
        f"[dim]threads:[/dim] [cyan]{state.threads}[/cyan]   "
        f"[dim]timeout:[/dim] [cyan]{state.timeout}s[/cyan]   "
        f"[dim]ports:[/dim] [cyan]{state.ports}[/cyan]   "
        f"[dim]output:[/dim] [cyan]{state.output_dir}[/cyan]"
    )
    console.print(WARN)
    _divider("─", "dim red")


def _section_table(title: str, items: list) -> Table:
    t = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    t.add_column("id",   style="bold cyan",   width=5,  justify="right")
    t.add_column("icon", width=3)
    t.add_column("name", style="bold white",  width=34)
    t.add_column("desc", style="dim",         width=55)
    for item in items:
        t.add_row(
            f"[{item['id']}]",
            item["icon"],
            item["label"],
            item["desc"],
        )
    return t


def _menu():
    _header()
    console.print()

    # Two-column layout for individual tools
    left  = _section_table("RECONNAISSANCE", RECON_SECTION)
    right = _section_table("WEB ANALYSIS",   WEB_SECTION)
    console.print(Columns([left, right], padding=(0, 4)))

    console.print()
    _divider("─", "dim")
    adv_left  = _section_table("ADVANCED ATTACKS  (32–38)", ADVANCED_SECTION[:7])
    adv_right = _section_table("ADVANCED ATTACKS  (39–45)", ADVANCED_SECTION[7:])
    console.print(Columns([adv_left, adv_right], padding=(0, 4)))

    console.print()
    _divider("─", "dim")
    owasp_t = _section_table("OWASP TOP 10  (A01–A10)", OWASP_SECTION)
    console.print(owasp_t)

    console.print()
    _divider("─", "dim")
    preset_t = _section_table("PRESET SCANS", SCAN_PRESETS)
    console.print(preset_t)

    console.print()
    _divider("─", "dim")
    console.print(
        "  [bold cyan][t][/bold cyan] Set target   "
        "[bold cyan][o][/bold cyan] Output dir   "
        "[bold cyan][th][/bold cyan] Threads   "
        "[bold cyan][to][/bold cyan] Timeout   "
        "[bold cyan][p][/bold cyan] Ports   "
        "[bold cyan][q][/bold cyan] Toggle quiet   "
        "[bold cyan][h][/bold cyan] Help   "
        "[bold cyan][0][/bold cyan] Exit"
    )
    _divider("═", "bold red")


def _prompt():
    tgt_hint = f" [dim]{state.target}[/dim]" if state.target else ""
    raw = console.input(f"[bold red]bb@toolkit[/bold red][dim red]:{tgt_hint}›[/dim red] ").strip()
    return raw.lower()


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [dim](enter to keep: {default})[/dim]" if default else ""
    val  = console.input(f"  [bold cyan]{prompt}[/bold cyan]{hint}: ").strip()
    return val if val else default


def _need_target() -> bool:
    if not state.target:
        console.print("  [yellow]No target set. Enter one now:[/yellow]")
        t = _ask("Target (domain or URL)")
        if t:
            state.target = t
        else:
            console.print("  [red]Aborted — no target.[/red]")
            return False
    return True


def _base_cmd() -> list[str]:
    cmd = [PYTHON, BB_PY, state.target]
    cmd += ["--threads", str(state.threads)]
    cmd += ["--timeout", str(state.timeout)]
    cmd += ["--output-dir", state.output_dir]
    cmd += ["--ports", state.ports]
    if state.quiet:
        cmd.append("--quiet")
    if state.json_only:
        cmd.append("--json-only")
    return cmd


def _build_module_cmd(keep: set[str]) -> list[str]:
    """Build a bb.py command that runs ONLY the modules in `keep`."""
    cmd  = _base_cmd()
    for mod_id, skip_flag in ALL_MODULES_BY_ID.items():
        if skip_flag and mod_id not in keep:
            cmd.append(skip_flag)
    return cmd


def _build_preset_cmd(extra_flags: list[str]) -> list[str]:
    cmd = _base_cmd()
    cmd += extra_flags
    return cmd


def _preview_and_run(cmd: list[str]):
    console.print()
    display = " \\\n    ".join(cmd)
    console.print(Panel(
        f"[bold green]{display}[/bold green]",
        title="[dim]command[/dim]",
        border_style="bold green",
        padding=(0, 1),
    ))
    _divider("─", "dim")
    console.print()
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Interrupted.[/yellow]")
    console.print()
    console.print("  [bold green]✓ Scan complete.[/bold green]  [dim]Exiting toolkit.[/dim]")
    console.print()
    sys.exit(0)


def _settings_target():
    t = _ask("New target (domain or URL)", state.target)
    if t:
        state.target = t
        console.print(f"  [green]Target set to:[/green] {state.target}")


def _settings_output():
    d = _ask("Output directory", state.output_dir)
    state.output_dir = d
    console.print(f"  [green]Output dir:[/green] {state.output_dir}")


def _settings_threads():
    v = _ask("Thread count", str(state.threads))
    try:
        state.threads = int(v)
        console.print(f"  [green]Threads:[/green] {state.threads}")
    except ValueError:
        console.print("  [red]Invalid number.[/red]")


def _settings_timeout():
    v = _ask("Timeout seconds", str(state.timeout))
    try:
        state.timeout = int(v)
        console.print(f"  [green]Timeout:[/green] {state.timeout}s")
    except ValueError:
        console.print("  [red]Invalid number.[/red]")


def _settings_ports():
    v = _ask("Port range [common/extended/all]", state.ports)
    if v in ("common", "extended", "all"):
        state.ports = v
        console.print(f"  [green]Ports:[/green] {state.ports}")
    else:
        console.print("  [red]Must be one of: common, extended, all[/red]")


def _help():
    console.print()
    console.print(Panel(
        "[bold]Individual modules[/bold] [dim](1–11)[/dim]\n"
        "  Pick any numbered module. You'll be asked to confirm\n"
        "  the target and the exact command before running.\n\n"
        "[bold]Preset scans[/bold] [dim](12–16)[/dim]\n"
        "  Pre-configured bundles that combine multiple modules.\n"
        "  Useful for a quick start without custom configuration.\n\n"
        "[bold]Settings[/bold]\n"
        "  [cyan]t[/cyan]  — change the active target\n"
        "  [cyan]o[/cyan]  — change the report output directory\n"
        "  [cyan]th[/cyan] — set thread count (default 20)\n"
        "  [cyan]to[/cyan] — set request timeout in seconds (default 5)\n"
        "  [cyan]p[/cyan]  — set port range: common / extended / all\n"
        "  [cyan]q[/cyan]  — toggle quiet mode (less terminal output)\n\n"
        "[bold]Tips[/bold]\n"
        "  • Run [bold]python bb.py --help[/bold] to see all raw flags.\n"
        "  • Reports are saved as HTML + JSON in the output directory.\n"
        "  • Only scan targets you own or have written permission to test.",
        title="[bold cyan]Help[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.input("  [dim]Press Enter to continue...[/dim]")


# ── Attack banner ──────────────────────────────────────────────────────────────

_BANNER_COLORS = {
    # recon
    "dns":            ("bold cyan",    "cyan"),
    "ports":          ("bold blue",    "blue"),
    "subdomains":     ("bold cyan",    "cyan"),
    "takeover":       ("bold red",     "red"),
    # web
    "waf":            ("bold yellow",  "yellow"),
    "dirfuzz":        ("bold blue",    "blue"),
    "crawl":          ("bold green",   "green"),
    "vulns":          ("bold red",     "red"),
    "xss-gen":        ("bold red",     "red"),
    "js":             ("bold yellow",  "yellow"),
    "cors-deep":      ("bold magenta", "magenta"),
    "smuggle":        ("bold red",     "red"),
    "redirect":       ("bold orange1", "orange1"),
    # owasp
    "owasp":          ("bold red",     "red"),
    # advanced
    "sqli":           ("bold red",     "red"),
    "auth":           ("bold blue",    "blue"),
    "pathtraversal":  ("bold yellow",  "yellow"),
    "cmdinject":      ("bold red",     "red"),
    "bizlogic":       ("bold magenta", "magenta"),
    "infodisclosure": ("bold yellow",  "yellow"),
    "accesscontrol":  ("bold red",     "red"),
    "fileupload":     ("bold orange1", "orange1"),
    "raceconditions": ("bold cyan",    "cyan"),
    "ssrf":           ("bold red",     "red"),
    "xxe":            ("bold red",     "red"),
    "nosqli":         ("bold green",   "green"),
    "apitest":        ("bold blue",    "blue"),
    "webcache":       ("bold yellow",  "yellow"),
}
_DEFAULT_COLORS = ("bold red", "red")


def _attack_banner(label: str, icon: str, desc: str, keep: set | None = None):
    """Print a big styled panel banner when an attack module is selected."""
    key = next(iter(keep), "") if keep else ""
    title_style, border_style = _BANNER_COLORS.get(key, _DEFAULT_COLORS)

    top_line = Text()
    top_line.append(f" {icon}  ", style="bold")
    top_line.append(label.upper(), style=title_style)

    desc_line = Text(f" {desc}", style="dim white")

    body = Text.assemble(top_line, "\n", desc_line)

    console.print()
    console.print(Panel(
        body,
        border_style=border_style,
        padding=(1, 6),
        expand=True,
    ))
    console.print()


# ── Module dispatch ────────────────────────────────────────────────────────────

def _handle_module(item: dict):
    if not _need_target():
        return
    _attack_banner(item["label"], item["icon"], item["desc"], item.get("keep"))
    cmd = _build_module_cmd(item["keep"])
    _preview_and_run(cmd)


def _handle_preset(item: dict):
    if not _need_target():
        return
    _attack_banner(item["label"], item["icon"], item["desc"])
    cmd = _build_preset_cmd(item["flags"])
    _preview_and_run(cmd)


# ── Route table ────────────────────────────────────────────────────────────────

def _build_routes():
    routes = {}
    for item in RECON_SECTION:
        routes[item["id"]] = ("module", item)
    for item in WEB_SECTION:
        routes[item["id"]] = ("module", item)
    for item in ADVANCED_SECTION:
        routes[item["id"]] = ("module", item)
    for item in OWASP_SECTION:
        routes[item["id"]] = ("module", item)
    for item in SCAN_PRESETS:
        routes[item["id"]] = ("preset", item)
    return routes


# ── Main loop ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty ToolKit — interactive menu launcher",
        add_help=True,
    )
    parser.add_argument("-t", "--target", default="", help="Pre-set target")
    parser.add_argument("-o", "--output-dir", default="reports", help="Report output directory")
    args = parser.parse_args()

    if args.target:
        state.target = args.target
    if args.output_dir:
        state.output_dir = args.output_dir

    routes = _build_routes()

    while True:
        _clear()
        _menu()

        try:
            choice = _prompt()
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n  [bold red]Goodbye.[/bold red]\n")
            sys.exit(0)

        if choice in ("0", "exit", "quit", "q"):
            console.print("\n  [bold red]Goodbye.[/bold red]\n")
            sys.exit(0)

        elif choice == "t":
            _settings_target()
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice == "o":
            _settings_output()
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice == "th":
            _settings_threads()
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice == "to":
            _settings_timeout()
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice == "p":
            _settings_ports()
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice in ("q", "quiet"):
            state.quiet = not state.quiet
            status = "ON" if state.quiet else "OFF"
            console.print(f"  [green]Quiet mode:[/green] {status}")
            console.input("  [dim]Press Enter to continue...[/dim]")

        elif choice == "h":
            _help()

        elif choice in routes:
            kind, item = routes[choice]
            if kind == "module":
                _handle_module(item)
            else:
                _handle_preset(item)

        else:
            console.print(f"  [red]Unknown option:[/red] [bold]{choice}[/bold]  — type a number or command from the menu.")
            console.input("  [dim]Press Enter to continue...[/dim]")


if __name__ == "__main__":
    main()
