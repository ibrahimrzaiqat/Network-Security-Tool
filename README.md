# Network Security Toolkit

A Python-based command-line tool for network reconnaissance and vulnerability
awareness. It scans a target for open ports, identifies what software is
running on them, and checks that software against the National Vulnerability
Database (NVD) for known CVEs — producing a structured JSON report at the end.

This project was built as a hands-on learning exercise in networking,
concurrency, and working with real-world security data sources.

## ⚠️ Legal & Ethical Use

**Only run this tool against systems you own, or have explicit written
permission to test.** Unauthorized scanning of networks or systems you do not
control may be illegal in your jurisdiction, regardless of intent.

Safe targets for practice:
- Your own machines (`127.0.0.1`, your own LAN devices)
- Deliberately vulnerable practice environments (e.g. Metasploitable)
- [scanme.nmap.org](https://scanme.nmap.org) — a host the Nmap project
  explicitly maintains for public scanning practice

## Features

- 🔍 **Multi-threaded TCP port scanner** — uses a bounded thread pool
  (`ThreadPoolExecutor`) to scan large port ranges quickly without
  overwhelming your system
- 📡 **Banner grabbing** — connects to open ports and reads service
  identification data, handling both services that announce themselves
  immediately (e.g. SSH) and services that require a request first (e.g. HTTP)
- 🧩 **Software/version extraction** — parses banners for `name/version`
  patterns using regex
- 🛡️ **CVE lookup via the NVD API** — checks identified software against
  the National Vulnerability Database, with local caching to avoid redundant
  API calls and automatic rate-limit-friendly delays
- 🎨 **Severity-based color coding** — critical (9.0+) and high (7.0+)
  severity CVEs are highlighted in the terminal
- 📄 **JSON report export** — every scan produces a timestamped,
  machine-readable report file
- ⚙️ **Configurable concurrency** — tune the number of scanning threads via
  a command-line flag, with a safety cap to prevent resource exhaustion

## Setup

Requirements: Python 3.8+

1. Clone the repository:
   ```bash
   git clone https://github.com/ibrahimrzaiqat/Network-Security-Tool.git
   cd network-security-toolkit
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

3. Get a free NVD API key (recommended — raises your rate limit significantly):
   - Register at https://nvd.nist.gov/developers/request-an-api-key
   - Create a file named `config.py` in the project folder:
     ```python
     NVD_API_KEY = "your-key-here"
     ```
   - This file is excluded from git via `.gitignore` — never commit your key

## Usage

```bash
python NetworkScanner.py <target_ip> <start_port> <end_port> [--workers N]
```

**Example:**
```bash
python NetworkScanner.py 127.0.0.1 1 1024 --workers 200
```

**Sample output:**
```
Scanning 127.0.0.1 from starting from port: 1, ending at port: 1024
Scan DONE, Total time taken: 1.02s
OPEN Ports: [8000]

Port: 8000: HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.4
...

Checking vulnerabilities for: Python 3.14.4
CVEs Found: 3
  - CVE-2023-XXXXX (Severity: 7.5)
    Info: A vulnerability was found in...

Scan complete! Full results saved to scan_report_127.0.0.1_1-1024_20260717_143022.json
```

Run `python NetworkScanner.py --help` for full argument details.

## How It Works

1. **Port scanning** — attempts a TCP connection to every port in the given
   range, using a thread pool to check many ports concurrently
2. **Banner grabbing** — for each open port, connects and either reads an
   unprompted greeting or sends a minimal HTTP request to provoke one
3. **Software identification** — extracts `name/version` pairs from the
   banner text using pattern matching
4. **CVE lookup** — queries the NVD API for each identified software/version,
   caching results locally to minimize redundant requests
5. **Reporting** — compiles everything into a timestamped JSON report

## Limitations

- TCP connect scanning only — no UDP scanning, no stealth/SYN scan techniques
- Software/version detection is regex-based and works best on services that
  expose a `name/version`-style banner; non-standard formats may be missed
- NVD keyword search can occasionally return loosely related CVEs rather than
  exact version matches — results should be reviewed, not treated as
  definitive
- No authentication or protocol-specific probes beyond a generic HTTP nudge —
  some services may not respond to banner-grab attempts at all

## License

This project is for educational purposes. Use responsibly.
