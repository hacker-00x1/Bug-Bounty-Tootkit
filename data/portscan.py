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

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


SERVICE_BANNERS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis",
    7001: "WebLogic",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "SAP",
}


def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        if port in (80, 8080, 8081, 8888):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 21:
            pass
        elif port == 22:
            pass
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        return banner[:200] if banner else None
    except Exception:
        return None


def scan_port(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = SERVICE_BANNERS.get(port, "Unknown")
            banner = grab_banner(host, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
            }
    except Exception:
        pass
    return None


def scan_ports(host: str, ports: list[int], threads: int = 30, timeout: float = 3.0) -> list[dict]:
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


def detect_service_vulns(port_info: dict) -> list[str]:
    issues = []
    port = port_info["port"]
    banner = port_info.get("banner", "") or ""

    if port == 21:
        issues.append("FTP exposed — check for anonymous login and clear-text credentials")
    if port == 23:
        issues.append("Telnet exposed — clear-text protocol, high risk")
    if port == 2375:
        issues.append("Docker daemon exposed without TLS — critical risk")
    if port == 6379:
        if "NOAUTH" in banner or banner == "":
            issues.append("Redis exposed — likely no authentication required")
    if port == 9200 and banner:
        issues.append("Elasticsearch exposed — check for unauthenticated access")
    if port == 27017:
        issues.append("MongoDB exposed — check for unauthenticated access")
    if port == 11211:
        issues.append("Memcached exposed — potential data exposure and DDoS amplification")

    version_patterns = [
        ("Apache/2.2", "Outdated Apache version detected"),
        ("Apache/2.0", "Very outdated Apache version detected"),
        ("nginx/1.0", "Outdated Nginx version detected"),
        ("OpenSSH_6", "Outdated OpenSSH version"),
        ("OpenSSH_5", "Very outdated OpenSSH version"),
        ("PHP/5.", "Outdated PHP version — EOL"),
        ("PHP/7.0", "Outdated PHP 7.0 — EOL"),
    ]
    for pattern, msg in version_patterns:
        if pattern.lower() in banner.lower():
            issues.append(msg)

    return issues


if __name__ == "__main__":
    pass
