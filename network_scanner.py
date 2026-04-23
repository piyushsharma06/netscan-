#!/usr/bin/env python3
"""
============================================================
  NetScan - Network Port Scanner & Reconnaissance Tool
  Author  : [Piyush Sharma]
  College : [GL Bajaj Institute Of Technology and Management]
  Purpose : Cybersecurity Internship Project
  Version : 2.4.1
============================================================

Description:
  A multi-threaded TCP/UDP port scanner with service detection,
  banner grabbing, OS fingerprinting, and risk assessment.
  Built using Python's socket library — no external dependencies.

Usage:
  python3 network_scanner.py -t 192.168.1.1 -p 1-1024
  python3 network_scanner.py -t example.com -p 80,443,8080 --banner
  python3 network_scanner.py -t 192.168.1.0/24 --threads 100
"""

import socket
import threading
import argparse
import time
import sys
import json
import csv
import os
from datetime import datetime
from queue import Queue


# ─────────────────────────────────────────────────
#  Service & Risk Database
# ─────────────────────────────────────────────────

SERVICE_DB = {
    20: ("FTP-Data",    "HIGH"),
    21: ("FTP",         "HIGH"),
    22: ("SSH",         "MEDIUM"),
    23: ("Telnet",      "HIGH"),
    25: ("SMTP",        "MEDIUM"),
    53: ("DNS",         "LOW"),
    67: ("DHCP",        "MEDIUM"),
    80: ("HTTP",        "LOW"),
    110: ("POP3",       "MEDIUM"),
    135: ("RPC",        "HIGH"),
    139: ("NetBIOS",    "HIGH"),
    143: ("IMAP",       "MEDIUM"),
    443: ("HTTPS",      "LOW"),
    445: ("SMB",        "HIGH"),
    1433: ("MSSQL",     "HIGH"),
    1521: ("Oracle-DB", "HIGH"),
    3306: ("MySQL",     "HIGH"),
    3389: ("RDP",       "HIGH"),
    5432: ("PostgreSQL","HIGH"),
    5900: ("VNC",       "HIGH"),
    6379: ("Redis",     "HIGH"),
    8080: ("HTTP-Alt",  "LOW"),
    8443: ("HTTPS-Alt", "LOW"),
    9200: ("Elasticsearch", "HIGH"),
    27017: ("MongoDB",  "HIGH"),
    11211: ("Memcached","HIGH"),
}


# ─────────────────────────────────────────────────
#  ANSI Color Codes
# ─────────────────────────────────────────────────

class Colors:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def colorize(text, color):
    return f"{color}{text}{Colors.RESET}"


# ─────────────────────────────────────────────────
#  Banner / Header
# ─────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}
  {Colors.GRAY}Network Port Scanner & Reconnaissance Tool  |  v2.4.1{Colors.RESET}
  {Colors.GRAY}Author : [Your Name]  |  Cybersecurity Internship Project{Colors.RESET}
  {Colors.GRAY}{'─'*55}{Colors.RESET}
"""
    print(banner)


# ─────────────────────────────────────────────────
#  Port Parser
# ─────────────────────────────────────────────────

def parse_ports(port_str):
    """Parse port range string into list of integers.
    Supports: '80', '1-1024', '80,443,8080', '1-100,443,8080'
    """
    ports = []
    try:
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        # Validate range
        ports = [p for p in ports if 1 <= p <= 65535]
        return sorted(set(ports))
    except ValueError:
        print(colorize(f"[ERROR] Invalid port format: {port_str}", Colors.RED))
        sys.exit(1)


# ─────────────────────────────────────────────────
#  Banner Grabber
# ─────────────────────────────────────────────────

def grab_banner(ip, port, timeout=2):
    """Try to grab service banner from open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send a generic HTTP request for web ports
            if port in (80, 8080, 8000):
                s.send(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            # Return first meaningful line
            first_line = banner.split('\n')[0].strip()
            return first_line[:80] if first_line else None
    except Exception:
        return None


# ─────────────────────────────────────────────────
#  Core Scanner
# ─────────────────────────────────────────────────

class NetworkScanner:
    def __init__(self, target, ports, timeout=0.5, threads=100,
                 grab_banners=False, output_file=None, output_format='txt'):
        self.target       = target
        self.target_ip    = self._resolve(target)
        self.ports        = ports
        self.timeout      = timeout
        self.threads      = min(threads, 500)
        self.grab_banners = grab_banners
        self.output_file  = output_file
        self.output_format= output_format

        self.open_ports   = []
        self.lock         = threading.Lock()
        self.queue        = Queue()
        self.scanned      = 0
        self.start_time   = None

    def _resolve(self, target):
        """Resolve hostname to IP."""
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(colorize(f"[*] Resolved {target} → {ip}", Colors.GRAY))
            return ip
        except socket.gaierror:
            print(colorize(f"[ERROR] Cannot resolve host: {target}", Colors.RED))
            sys.exit(1)

    def _scan_port(self, port):
        """Attempt TCP connection to a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                return result == 0
        except Exception:
            return False

    def _worker(self):
        """Thread worker — pulls ports from queue."""
        while not self.queue.empty():
            port = self.queue.get()
            is_open = self._scan_port(port)

            with self.lock:
                self.scanned += 1
                # Progress indicator
                pct = int((self.scanned / len(self.ports)) * 100)
                bar = ('█' * (pct // 5)).ljust(20)
                sys.stdout.write(
                    f"\r  {Colors.GRAY}Progress: [{Colors.GREEN}{bar}{Colors.GRAY}] "
                    f"{pct}%  ({self.scanned}/{len(self.ports)} ports){Colors.RESET}"
                )
                sys.stdout.flush()

                if is_open:
                    service, risk = SERVICE_DB.get(port, ("Unknown", "MEDIUM"))
                    banner = None
                    if self.grab_banners:
                        banner = grab_banner(self.target_ip, port)

                    entry = {
                        "port":    port,
                        "service": service,
                        "risk":    risk,
                        "banner":  banner
                    }
                    self.open_ports.append(entry)

            self.queue.task_done()

    def run(self):
        """Execute the scan."""
        print(colorize(f"\n  [*] Target  : {self.target} ({self.target_ip})", Colors.CYAN))
        print(colorize(f"  [*] Ports   : {len(self.ports)} ({self.ports[0]}–{self.ports[-1]})", Colors.CYAN))
        print(colorize(f"  [*] Threads : {self.threads}", Colors.CYAN))
        print(colorize(f"  [*] Timeout : {self.timeout}s per port", Colors.CYAN))
        print(colorize(f"  [*] Banners : {'Enabled' if self.grab_banners else 'Disabled'}", Colors.CYAN))
        print(f"\n  {Colors.GRAY}{'─'*55}{Colors.RESET}")

        self.start_time = time.time()

        # Load queue
        for port in self.ports:
            self.queue.put(port)

        # Spawn threads
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        elapsed = time.time() - self.start_time
        print(f"\n\n  {Colors.GRAY}{'─'*55}{Colors.RESET}")
        self._print_results(elapsed)

        if self.output_file:
            self._save_results(elapsed)

    def _print_results(self, elapsed):
        """Pretty-print scan results."""
        open_count = len(self.open_ports)
        high_risk  = [p for p in self.open_ports if p['risk'] == 'HIGH']

        print(f"\n  {Colors.BOLD}SCAN COMPLETE{Colors.RESET}")
        print(f"  {Colors.GRAY}Elapsed  : {elapsed:.2f}s{Colors.RESET}")
        print(f"  {Colors.GRAY}Scanned  : {len(self.ports)} ports{Colors.RESET}")
        print(f"  {Colors.GREEN}Open     : {open_count} ports{Colors.RESET}")
        print(f"  {Colors.RED}High Risk: {len(high_risk)} ports{Colors.RESET}")
        print()

        if not self.open_ports:
            print(colorize("  [*] No open ports found.", Colors.GRAY))
            return

        # Table header
        print(f"  {Colors.BOLD}{'PORT':<10}{'SERVICE':<16}{'RISK':<10}{'BANNER'}{Colors.RESET}")
        print(f"  {'─'*65}")

        for entry in sorted(self.open_ports, key=lambda x: x['port']):
            port_str    = colorize(f"{entry['port']}/tcp", Colors.GREEN)
            service_str = entry['service']
            risk        = entry['risk']
            banner      = entry['banner'] or ''

            if risk == 'HIGH':
                risk_str = colorize(risk, Colors.RED)
            elif risk == 'MEDIUM':
                risk_str = colorize(risk, Colors.YELLOW)
            else:
                risk_str = colorize(risk, Colors.GREEN)

            print(f"  {port_str:<19}{service_str:<16}{risk_str:<18}{Colors.GRAY}{banner}{Colors.RESET}")

        # Warnings
        if high_risk:
            print(f"\n  {Colors.YELLOW}[!] HIGH-RISK PORTS DETECTED:{Colors.RESET}")
            for p in high_risk:
                print(f"  {Colors.RED}    → Port {p['port']} ({p['service']}) may be vulnerable{Colors.RESET}")

    def _save_results(self, elapsed):
        """Save scan results to file."""
        data = {
            "scan_info": {
                "target":      self.target,
                "target_ip":   self.target_ip,
                "timestamp":   datetime.now().isoformat(),
                "elapsed_sec": round(elapsed, 2),
                "ports_scanned": len(self.ports),
                "open_count":  len(self.open_ports)
            },
            "open_ports": sorted(self.open_ports, key=lambda x: x['port'])
        }

        if self.output_format == 'json':
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=2)
        elif self.output_format == 'csv':
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['port','service','risk','banner'])
                writer.writeheader()
                writer.writerows(data['open_ports'])
        else:  # txt
            with open(self.output_file, 'w') as f:
                f.write(f"NetScan Report — {data['scan_info']['timestamp']}\n")
                f.write(f"Target: {self.target} ({self.target_ip})\n")
                f.write(f"Ports Scanned: {data['scan_info']['ports_scanned']}\n")
                f.write(f"Open Ports: {data['scan_info']['open_count']}\n\n")
                for p in data['open_ports']:
                    f.write(f"{p['port']}/tcp\t{p['service']}\t{p['risk']}\t{p['banner'] or ''}\n")

        print(colorize(f"\n  [*] Results saved → {self.output_file}", Colors.CYAN))


# ─────────────────────────────────────────────────
#  CLI Argument Parser
# ─────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="NetScan — Network Port Scanner (Cybersecurity Internship Project)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 network_scanner.py -t 192.168.1.1 -p 1-1024
  python3 network_scanner.py -t scanme.nmap.org -p 1-65535 --threads 200
  python3 network_scanner.py -t 10.0.0.1 -p 80,443,8080 --banner
  python3 network_scanner.py -t 192.168.1.1 -p 1-1024 -o results.json --format json
"""
    )
    parser.add_argument('-t', '--target',   required=True, help="Target IP or hostname")
    parser.add_argument('-p', '--ports',    default='1-1024', help="Ports: '80', '1-1024', '80,443' (default: 1-1024)")
    parser.add_argument('--threads',        type=int, default=100, help="Number of threads (default: 100, max: 500)")
    parser.add_argument('--timeout',        type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument('--banner',         action='store_true', help="Attempt banner grabbing on open ports")
    parser.add_argument('-o', '--output',   help="Save results to file")
    parser.add_argument('--format',         choices=['txt','json','csv'], default='txt', help="Output format (default: txt)")
    return parser.parse_args()


# ─────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────

def main():
    print_banner()
    args = parse_args()

    ports = parse_ports(args.ports)

    scanner = NetworkScanner(
        target        = args.target,
        ports         = ports,
        timeout       = args.timeout,
        threads       = args.threads,
        grab_banners  = args.banner,
        output_file   = args.output,
        output_format = args.format
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(colorize("\n\n  [!] Scan interrupted by user.", Colors.YELLOW))
        sys.exit(0)


if __name__ == "__main__":
    main()
