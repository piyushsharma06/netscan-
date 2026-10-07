# NetScan — Network Port Scanner & Reconnaissance Tool

> Cybersecurity Internship Project | Python | Multi-threaded

## Features

- **Multi-threaded TCP scanning** — scan 1000 ports in seconds
- **Service detection** — identifies 25+ common services (HTTP, SSH, MySQL, RDP...)
- **Risk assessment** — flags HIGH / MEDIUM / LOW risk ports
- **Banner grabbing** — retrieves service version info from open ports
- **Multiple output formats** — TXT, JSON, CSV
- **Progress bar** — real-time scan progress in terminal

## Installation

```bash
git clone https://github.com/piyushsharma06/netscan-.git
cd netscan-
python3 network_scanner.py --help
```

No external dependencies — uses Python standard library only.

## Usage

```bash
# Basic scan (ports 1-1024)
python3 network_scanner.py -t 192.168.1.1

# Full port range with 200 threads
python3 network_scanner.py -t 192.168.1.1 -p 1-65535 --threads 200

# Specific ports with banner grabbing
python3 network_scanner.py -t example.com -p 80,443,8080,3306 --banner

# Save results as JSON
python3 network_scanner.py -t 10.0.0.1 -p 1-1024 -o results.json --format json
```

## Sample Output

```
  PORT      SERVICE         RISK      BANNER
  ─────────────────────────────────────────────────────────────
  22/tcp    SSH             MEDIUM    OpenSSH 8.9p1 Ubuntu
  80/tcp    HTTP            LOW       Apache/2.4.54 (Ubuntu)
  443/tcp   HTTPS           LOW
  3306/tcp  MySQL           HIGH      8.0.32 MySQL Community Server
  3389/tcp  RDP             HIGH

  [!] HIGH-RISK PORTS DETECTED:
      → Port 3306 (MySQL) may be vulnerable
      → Port 3389 (RDP) may be vulnerable
```

## Legal Disclaimer

This tool is for **educational purposes only**. Only scan networks and systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

## Technologies Used

- Python 3.x
- `socket` — TCP connections
- `threading` + `Queue` — concurrent scanning
- `argparse` — CLI interface
- `json`, `csv` — result export

## Author

[Piyush Sharma] |  Cybersecurity Internship Project 2026
"# netscan-" 
