import os
import glob
import json
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from NetworkScanner import run_scan

from google import genai
from google.genai import types
from config import GEMINI_API_KEY

client = genai.Client(api_key=GEMINI_API_KEY)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR

app = FastAPI(title="Agentic Security Dashboard")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

SCAN_STATUS = {"status": "idle", "file": None, "error": None}


class ScanRequest(BaseModel):
    target_ip: str
    start_port: int
    end_port: int
    workers: int = 100


def _run_scan_task(target_ip: str, start_port: int, end_port: int, workers: int):
    global SCAN_STATUS
    try:
        filename = run_scan(target_ip, start_port, end_port, workers)
        if filename:
            SCAN_STATUS["status"] = "complete"
            SCAN_STATUS["file"] = filename
            SCAN_STATUS["error"] = None
        else:
            SCAN_STATUS["status"] = "error"
            SCAN_STATUS["error"] = "Scan returned no report (check port range)."
    except Exception as e:
        SCAN_STATUS["status"] = "error"
        SCAN_STATUS["error"] = str(e)


def severity_class(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def build_report_payload(filename: str) -> dict:
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    with open(path) as f:
        data = json.load(f)

    ports = []
    for port, findings in data.get("results", {}).items():
        max_sev = None
        total_cves = 0
        for finding in findings:
            total_cves += finding.get("cves_found", 0) or 0
            for cve in (finding.get("cve_details") or []):
                sev = cve.get("severity")
                if sev is not None and (max_sev is None or float(sev) > max_sev):
                    max_sev = float(sev)

        ports.append({
            "port": port,
            "findings": findings,
            "max_severity": max_sev,
            "severity_class": severity_class(max_sev),
            "total_cves": total_cves,
        })

    ports.sort(key=lambda p: (p["max_severity"] is None, -(p["max_severity"] or 0)))

    summary = {
        "open_ports": len(ports),
        "total_cves": sum(p["total_cves"] for p in ports),
        "critical": sum(1 for p in ports if p["severity_class"] == "critical"),
        "high": sum(1 for p in ports if p["severity_class"] == "high"),
    }

    return {
        "target_ip": data.get("target_ip", "unknown"),
        "file": filename,
        "summary": summary,
        "ports": ports,
    }


def find_latest_report() -> Optional[str]:
    reports = sorted(REPORTS_DIR.glob("scan_report_*.json"), key=os.path.getmtime, reverse=True)
    return reports[0].name if reports else None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.post("/api/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if SCAN_STATUS["status"] == "scanning":
        raise HTTPException(status_code=409, detail="A scan is already running")

    SCAN_STATUS["status"] = "scanning"
    SCAN_STATUS["file"] = None
    SCAN_STATUS["error"] = None

    background_tasks.add_task(_run_scan_task, req.target_ip, req.start_port, req.end_port, req.workers)
    return {"status": "started"}


@app.get("/api/scan/status")
def scan_status():
    return SCAN_STATUS


@app.get("/api/report")
def api_report(file: Optional[str] = Query(default=None)):
    filename = file or find_latest_report()
    if not filename:
        raise HTTPException(status_code=404, detail="No scan reports found yet")
    return build_report_payload(filename)


def build_advice_prompt(report_data: dict) -> str:
    prompt_lines = [
        "You are an expert SOC Analyst and Linux Security Engineer.",
        "Review the following network vulnerability scan summary for an Ubuntu/WSL system.",
        "For each open port with vulnerabilities, strictly follow this EXACT markdown format:",
        "",
        "### Port [Number]: [Service Name]",
        "#### 1. Risk",
        "[1-2 sentence explanation of the threat, explicitly naming the specific CVE IDs provided.]",
        "#### 2. Mitigation",
        "[Brief explanation of the fix]",
        "```bash",
        "# [Comment explaining the command]",
        "[Exact terminal command to fix the issue]",
        "```",
        "",
        "CRITICAL RULES:",
        "1. You MUST wrap all terminal commands inside ```bash code blocks so the UI renders them correctly.",
        "2. Do not use generic summaries; name the specific CVEs from the data.",
        "3. Only provide Ubuntu (apt/ufw/systemctl) commands.",
        "\n================ DATA INPUT ================"
    ]
    
    for p in report_data.get("ports", []):
        port_num = p.get("port")
        max_sev = p.get("max_severity", "None")
        
        if max_sev is None or float(max_sev) < 4.0:
            continue
            
        prompt_lines.append(f"\nPort {port_num} (Highest CVSS: {max_sev}):")
        
        for finding in p.get("findings", []):
            software = finding.get("software", "Unknown")
            cves = finding.get("cve_details", [])
            
            if cves:
                prompt_lines.append(f"  Service: {software}")
                for cve in cves[:3]:
                    cve_id = cve.get("id")
                    sev = cve.get("severity")
                    desc = str(cve.get("description", ""))[:100] + "..."
                    prompt_lines.append(f"  - {cve_id} (Sev: {sev}): {desc}")

    return "\n".join(prompt_lines)


@app.get("/api/agent")
def api_agent():
    filename = find_latest_report()
    if not filename:
        raise HTTPException(status_code=404, detail="No scan reports found. Run a scan first.")
    
    report_data = build_report_payload(filename)
    
    if report_data["summary"]["open_ports"] == 0:
        return {"advice": "No open ports detected. Your network is currently secure."}

    if report_data["summary"]["total_cves"] == 0:
        return {"advice": "Open ports were detected, but no banners or CVEs were found. No AI analysis is required."}

    prompt = build_advice_prompt(report_data)
    
    if "Port " not in prompt:
        return {"advice": "Ports are open, but no high-severity vulnerabilities were found. No immediate action required."}
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(model="gemini-3.5-flash-lite", contents=prompt, config=types.GenerateContentConfig(temperature=0.2, max_output_tokens=800))
            return {"advice": response.text}

        except Exception as e:
            erorr_msg= str(e)
            # If it is a 503 Server Overload and we have retries left, wait and try again
            if "503" in erorr_msg and attempt < max_retries -1:
                print(f"Server overloaded. Retrying in 3 seconds... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(3)
                continue
            raise HTTPException(status_code=500, detail=f"AI generation failed: {str(e)}")