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
import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import dns.resolver
import dns.reversename


def get_ip(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def dns_lookup(target: str, record_types: list[str]) -> dict:
    """Resolve all DNS record types in parallel instead of sequentially."""
    results: dict = {}

    def _resolve(rtype: str) -> tuple[str, list[str]]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        try:
            answers = resolver.resolve(target, rtype)
            return rtype, [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return rtype, []
        except Exception:
            return rtype, []

    with ThreadPoolExecutor(max_workers=len(record_types)) as executor:
        futures = {executor.submit(_resolve, rt): rt for rt in record_types}
        for future in as_completed(futures):
            rtype, records = future.result()
            results[rtype] = records

    return results


def reverse_dns(ip: str) -> Optional[str]:
    try:
        rev_name = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(str(rev_name), "PTR")
        return str(result[0])
    except Exception:
        return None


def crtsh_subdomains(domain: str) -> list[str]:
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "BugBountyTool/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if line.endswith(f".{domain}") or line == domain:
                        subdomains.add(line)
    except Exception:
        pass
    return sorted(subdomains)


def brute_subdomains(domain: str, wordlist: list[str], threads: int = 20, timeout: int = 3) -> list[dict]:
    found = []

    def check(sub: str) -> Optional[dict]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
            if ip:
                return {"subdomain": fqdn, "ip": ip[0][4][0]}
        except socket.gaierror:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])


def get_whois(domain: str) -> dict:
    result = {
        "raw": "",
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "name_servers": [],
        "emails": [],
    }
    try:
        import whois as pythonwhois
        w = pythonwhois.whois(domain)
        result["raw"] = str(w)
        result["registrar"] = str(w.registrar) if w.registrar else None
        result["creation_date"] = str(w.creation_date) if w.creation_date else None
        result["expiry_date"] = str(w.expiration_date) if w.expiration_date else None
        result["name_servers"] = [str(ns) for ns in (w.name_servers or [])]
        result["emails"] = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
    except ImportError:
        result["raw"] = _socket_whois(domain)
        result = _parse_whois_raw(result)
    except Exception as e:
        result["raw"] = str(e)
    return result


def _socket_whois(domain: str) -> str:
    tld_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
    }
    tld = domain.split(".")[-1].lower()
    server = tld_servers.get(tld, f"whois.nic.{tld}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        return response.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_whois_raw(result: dict) -> dict:
    raw = result["raw"]
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"(?:Expiry|Expiration) Date:\s*(.+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            result[key] = m.group(1).strip()
    ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
    result["name_servers"] = [ns.strip() for ns in ns_matches]
    email_matches = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw)
    result["emails"] = list(set(email_matches))
    return result


if __name__ == "__main__":
    pass
