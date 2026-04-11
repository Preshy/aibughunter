"""Web dashboard API and interface for AI Bug Hunter."""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aibughunter.core.database import Database
from aibughunter.core.scope import ScopeManager

app = FastAPI(
    title="AI Bug Hunter",
    description="Web dashboard for AI-powered bug hunting",
    version="0.1.0",
)

db = Database()


# ===== API Endpoints =====

@app.get("/api/stats")
def get_stats():
    """Get vulnerability statistics."""
    stats = db.get_stats()
    
    # Add recent scans
    scans = db.list_scans(limit=10)
    stats["recent_scans"] = scans
    
    # Add tool stats
    tool_usage = db.get_tool_stats()
    stats["tool_usage"] = tool_usage
    
    return stats


@app.get("/api/findings")
def get_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    target: Optional[str] = None,
    limit: int = 100,
):
    """Query findings with filters."""
    findings = db.get_findings(
        scan_id=scan_id,
        severity=severity,
        status=status,
        target=target,
        limit=limit,
    )
    return {"total": len(findings), "findings": findings}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    """Get specific finding by ID."""
    findings = db.get_findings()
    finding = next((f for f in findings if f["id"] == finding_id), None)
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return finding


@app.put("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: str, status: str):
    """Update finding status."""
    db.update_finding_status(finding_id, status)
    return {"status": "ok", "finding_id": finding_id, "new_status": status}


@app.get("/api/scans")
def list_scans(limit: int = 20):
    """List recent scans."""
    scans = db.list_scans(limit=limit)
    return {"total": len(scans), "scans": scans}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    """Get scan details."""
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings for this scan
    findings = db.get_findings(scan_id=scan_id)
    scan["findings"] = findings
    
    return scan


@app.get("/api/targets")
def list_targets(program: Optional[str] = None, scope_type: Optional[str] = None):
    """List targets."""
    targets = db.list_targets(program=program, scope_type=scope_type)
    return {"total": len(targets), "targets": targets}


@app.post("/api/targets")
def add_target(target: str, scope_type: str = "in", program: str = "default"):
    """Add target to scope."""
    db.add_target(target, scope_type, program)
    return {"status": "ok", "target": target}


@app.delete("/api/targets/{target}")
def remove_target(target: str):
    """Remove target from scope."""
    db.remove_target(target)
    return {"status": "ok", "target": target}


@app.get("/api/programs")
def list_programs():
    """List bug bounty programs."""
    programs = db.list_programs()
    return {"total": len(programs), "programs": programs}


@app.get("/api/tools/stats")
def get_tool_stats():
    """Get tool usage statistics."""
    return db.get_tool_stats()


# ===== Dashboard UI =====

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the main dashboard."""
    dashboard_file = Path(__file__).parent / "dashboard.html"
    if dashboard_file.exists():
        with open(dashboard_file) as f:
            return f.read()
    return HTMLResponse(content="<h1>Dashboard file not found</h1>")


# ===== Data Models =====

class TargetRequest(BaseModel):
    target: str
    scope_type: str = "in"
    program: str = "default"
    notes: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str


# ===== Mount Static Files =====

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
