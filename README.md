# Agentic Security Dashboard 🛡️

A portable, driver-free network vulnerability scanner that pairs a concurrent Python scanning engine with an AI remediation agent. It discovers local devices, identifies active services, crosses-references them against the National Vulnerability Database (NVD), and generates actionable, ready-to-run `.sh` patch scripts using Google's Gemini LLM.

This project evolved from a command-line learning exercise into a fully packaged, self-terminating web dashboard designed to bridge the gap between vulnerability discovery and immediate system remediation.

## ⚠️ Legal & Ethical Use

**Only run this tool against systems you own, or have explicit written permission to test.** Unauthorized scanning of networks or systems you do not control may be illegal in your jurisdiction, regardless of intent.

Safe targets for practice:

* Your own machines (`127.0.0.1`, your own LAN devices)
* Deliberately vulnerable practice environments (e.g., Metasploitable, local VMs)
* [scanme.nmap.org](https://scanme.nmap.org?utm_source=gemini) — a host the Nmap project explicitly maintains for public scanning practice

---

## What Was Used (Architecture & Tech Stack)

The application is built to be entirely self-contained without requiring heavy database installations or external networking drivers (like Npcap).

* **Backend Engine:** Python, FastAPI, and Uvicorn.
* **Concurrency:** `concurrent.futures.ThreadPoolExecutor` for high-speed network sweeps and port scanning.
* **Frontend:** Vanilla HTML, CSS, and JavaScript rendered via Jinja2 templates.
* **AI Provider:** Google GenAI SDK (Gemini Flash models).
* **Storage:** Ephemeral local JSON files (bypassing SQLite for maximum portability).
* **Packaging:** PyInstaller (compiled into a single `--noconsole` Windows `.exe` with automated heartbeat process management).

---

## Critical API Dependencies

For the dashboard to function correctly, it requires two external APIs. These must be configured via a `config.env` file.

### 1. National Vulnerability Database (NVD) API

* **Requirement:** While the NVD API can technically be queried without a key, public rate limits are extremely strict and will cause scans to fail. A free API key is heavily recommended. Get one at: [NVD API Request](https://nvd.nist.gov/developers/request-an-api-key?utm_source=gemini).

### 2. Google Gemini API

* **Requirement:** A valid Google Gemini API key is mandatory for the "Generate AI Mitigation Report" feature to function. Get one at: [Google AI Studio](https://aistudio.google.com/?utm_source=gemini).

---

## Core Features

* **Driver-Free Network Discovery:** Identifies live hosts and resolves NetBIOS/DNS hostnames natively using pure Python and OS-level ICMP sweeps.
* **Concurrent TCP Port Scanning:** Multi-threaded TCP connect scanning optimized for speed. It grabs banners from open ports, handling both immediate announcements (SSH) and request-prompted services (HTTP).
* **Automated CVE Mapping & UI Highlighting:** Extracts software versions via regex and queries the NVD. Results are color-coded in the UI by severity (Critical = 9.0+, High = 7.0+).
* **Agentic Remediation:** Pipes scan results to Gemini, outputting specific threat mitigations and providing a one-click **Download .sh Patch Script** button to export actionable fixes.
* **Zero-Setup Portability:** Bundled into a single Windows `.exe`. A browser-side heartbeat monitor ensures the background Uvicorn server safely terminates itself 10 seconds after the browser tab is closed, preventing zombie processes.

---

## Installation & Setup

### Option 1: Portable Windows Executable (Recommended)

1. Download `AgenticSecurityDashboard.exe` from the **Releases** tab.
2. Place the `.exe` in an empty directory.
3. In the exact same directory, create a text file named `config.env` and populate it with your API keys:
```env
NVD_API_KEY=your_nvd_key_here
GEMINI_API_KEY=your_gemini_key_here

```


4. Double-click the `.exe`. The server will start silently in the background. Navigate to `[http://127.0.0.1:8000](http://127.0.0.1:8000)` in your web browser.

### Option 2: Run from Source

1. Clone the repository and install the dependencies:
```bash
git clone https://github.com/ibrahimrzaiqat/Agentic-Security-Dashboard.git
cd Agentic-Security-Dashboard
pip install fastapi uvicorn google-genai requests pydantic jinja2

```


2. Create your `config.env` file in the root directory.
3. Launch the application:
```bash
python launcher.py

```


4. Open `[http://127.0.0.1:8000](http://127.0.0.1:8000)` in your browser.

---

## Usage Workflow

1. **Discover:** Enter your subnet (or leave blank to auto-detect) and click **Discover Devices** to map active local IPs and hostnames.
2. **Scan:** Input a target IP, define a port range (e.g., `1-1024`), and click **Start Scan**.
3. **Analyze:** Review the generated JSON-backed vulnerability report in the UI, sorted by highest CVSS severity.
4. **Remediate:** Click **Generate AI Mitigation Report** to send the findings to the Gemini agent.
5. **Patch:** Click **Download .sh Patch Script** to export the AI's terminal commands. Transfer this `.sh` file to your target Linux/WSL environment to apply the patches.