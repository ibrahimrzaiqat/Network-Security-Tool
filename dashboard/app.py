import os
import glob
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from NetworkScanner import run_scan

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
