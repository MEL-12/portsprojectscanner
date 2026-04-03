#!/usr/bin/env python3
"""
Network Port Scanner
Scans open ports on a target system and displays service/version info.
Usage: python scanner.py <target> [-p PORTS] [-t TIMEOUT] [--udp]
"""

import argparse
import socket
import sys
import nmap
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = r"""
  ____           _     ____                                 
 |  _ \ ___  __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |_) / _ \/ _` | |_\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | (_| |  _|___) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/ \__,_|_| |____/ \___\__,_|_| |_|_| |_|\___|_|   
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner — detects open ports and service info",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py scanme.nmap.org
  python scanner.py 192.168.1.1 -p 1-65535
  python scanner.py 10.0.0.1 -p 80,443,8080 -t 0.5
  sudo python scanner.py 192.168.1.1 --udp
        """
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range or list (default: 1-1024). Examples: 1-65535 or 80,443,8080"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds per port (default: 1.0)"
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP scan (requires root/admin privileges)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to a text file (optional)"
    )
    return parser.parse_args()


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(Fore.RED + f"[!] Cannot resolve host: '{target}'. Check the address and try again.")
        sys.exit(1)


def run_scan(ip: str, ports: str, udp: bool, timeout: float):
    """Run nmap scan with service and version detection."""
    nm = nmap.PortScanner()

    # Build nmap arguments
    nmap_args = f"-sV --version-intensity 5 --host-timeout {int(timeout * 1000)}ms"
    if udp:
        nmap_args += " -sU"

    print(Fore.CYAN + f"\n[*] Starting scan on {ip} | Ports: {ports}")
    print(Fore.CYAN + f"[*] Nmap arguments: {nmap_args}\n")

    try:
        nm.scan(hosts=ip, ports=ports, arguments=nmap_args)
    except nmap.PortScannerError as e:
        print(Fore.RED + f"[!] Nmap error: {e}")
        print(Fore.YELLOW + "[!] Make sure nmap is installed: https://nmap.org/download.html")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Unexpected error during scan: {e}")
        sys.exit(1)

    return nm


def extract_results(nm, ip: str) -> list:
    """Parse nmap results into a list of port dictionaries."""
    results = []

    if ip not in nm.all_hosts():
        return results

    host_data = nm[ip]

    for proto in host_data.all_protocols():
        sorted_ports = sorted(host_data[proto].keys())
        for port in sorted_ports:
            info = host_data[proto][port]
            results.append({
                "port":      port,
                "proto":     proto,
                "state":     info.get("state", "unknown"),
                "name":      info.get("name", ""),
                "product":   info.get("product", ""),
                "version":   info.get("version", ""),
                "extrainfo": info.get("extrainfo", ""),
                "cpe":       info.get("cpe", ""),
            })

    return results


def format_version(r: dict) -> str:
    """Build a clean version string from product/version/extrainfo."""
    parts = [r["product"], r["version"], r["extrainfo"]]
    return " ".join(p for p in parts if p).strip()


def print_results(results: list, target: str, ip: str) -> str:
    """Print scan results in a formatted table. Returns the output as a string."""
    lines = []

    header = f"\n  Target  : {target}"
    if target != ip:
        header += f"  ({ip})"
    lines.append(header)
    lines.append(f"  Ports   : {len(results)} scanned\n")

    col = f"  {'PORT':<12}{'STATE':<12}{'SERVICE':<16}{'VERSION'}"
    divider = "  " + "─" * 64
    lines.append(col)
    lines.append(divider)

    open_count = 0
    for r in results:
        state = r["state"]
        version_str = format_version(r)

        if state == "open":
            state_color = Fore.GREEN
            open_count += 1
        elif state == "filtered":
            state_color = Fore.YELLOW
        elif state == "closed":
            state_color = Fore.RED
        else:
            state_color = Fore.WHITE

        port_str    = f"{r['port']}/{r['proto']}"
        line = (
            f"  {state_color}{port_str:<12}{state:<12}"
            f"{r['name']:<16}{version_str}{Style.RESET_ALL}"
        )
        lines.append(line)

    lines.append("  " + "─" * 64)
    lines.append(
        f"\n  {Fore.GREEN}[+] {open_count} open port(s) "
        f"found out of {len(results)} scanned.{Style.RESET_ALL}\n"
    )

    output = "\n".join(lines)
    print(output)
    return output


def save_results(output: str, filepath: str):
    """Save plain-text results (strip ANSI color codes) to a file."""
    import re
    ansi_escape = re.compile(r'\x1B\[[0-9;]*m')
    clean = ansi_escape.sub('', output)
    with open(filepath, 'w') as f:
        f.write(clean)
    print(Fore.CYAN + f"[*] Results saved to: {filepath}")


def main():
    print(Fore.CYAN + BANNER)

    args = parse_args()

    # Legal reminder
    print(Fore.YELLOW + "  [!] Only scan systems you own or have explicit permission to scan.\n")

    # Resolve host
    ip = resolve_host(args.target)
    if ip != args.target:
        print(Fore.WHITE + f"  [*] Resolved {args.target} → {ip}")

    # Run scan
    nm = run_scan(ip, args.ports, args.udp, args.timeout)

    # Parse results
    results = extract_results(nm, ip)

    if not results:
        print(Fore.YELLOW + "\n[!] No results returned. The host may be down or blocking all scans.")
        sys.exit(0)

    # Display results
    output = print_results(results, args.target, ip)

    # Optionally save
    if args.output:
        save_results(output, args.output)


if __name__ == "__main__":
    main()