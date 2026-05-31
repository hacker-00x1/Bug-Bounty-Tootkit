# Bug Bounty Tool Kit  ─  by Hacker00X1  |  Authorized use only
"""
Shared banner module — imported by all data/ modules.
Call show() to print the ASCII art panel at module startup.
"""

_ASCII = """\
\033[1;31m██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗ ██╗\033[0m
\033[1;31m██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚██╗██╔╝███║\033[0m
\033[1;31m███████║███████║██║     █████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║ ╚███╔╝  ██║\033[0m
\033[1;31m██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ██╔██╗  ██║\033[0m
\033[1;31m██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝██╔╝ ██╗ ██║\033[0m
\033[2;31m╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝\033[0m"""

_LINE = "\033[1;31m" + "─" * 80 + "\033[0m"
_SUBTITLE = "\033[2m  Bug Bounty Tool Kit  ─  Recon · Scan · Exploit · Report\033[0m"
_WARN = "\033[2;31m  ⚠  Only scan targets you own or have explicit written permission to test.\033[0m"


def show(module_name: str = "", target: str = ""):
    """Print the big ASCII art banner to stdout."""
    print(_LINE)
    print(_ASCII)
    print(_SUBTITLE)
    if module_name:
        print(f"\033[1;36m  Module: {module_name}\033[0m", end="")
        if target:
            print(f"  \033[2m→\033[0m  \033[1;32m{target}\033[0m", end="")
        print()
    print(_WARN)
    print(_LINE)


def rich_markup() -> str:
    """Return the banner as a Rich markup string (for use with Console.print)."""
    lines = [
        "[bold red]██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗ ██╗[/bold red]",
        "[bold red]██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗╚██╗██╔╝███║[/bold red]",
        "[bold red]███████║███████║██║     █████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║ ╚███╔╝  ██║[/bold red]",
        "[bold red]██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ██╔██╗  ██║[/bold red]",
        "[bold red]██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║╚██████╔╝╚██████╔╝██╔╝ ██╗ ██║[/bold red]",
        "[dim red]╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝[/dim red]",
    ]
    return "\n".join(lines)
