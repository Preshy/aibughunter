"""Marketing landing page with payment integration."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import os
import uuid
import sqlite3
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

app = FastAPI(
    title="AI Bug Hunter",
    description="AI-Powered Bug Bounty Hunting Platform",
    version="1.0.0",
)

# Templates directory
templates_dir = Path(__file__).parent / "templates"

def read_template(name: str) -> str:
    """Read HTML template file."""
    template_file = templates_dir / name
    if template_file.exists():
        return template_file.read_text()
    return f"<h1>Template not found: {name}</h1>"

# Database for scan requests and payments
db_path = Path(__file__).parent.parent.parent / "data" / "marketing.db"
db_path.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_db():
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Initialize marketing database."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_requests (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'quick',
                status TEXT DEFAULT 'pending',
                payment_status TEXT DEFAULT 'unpaid',
                amount REAL DEFAULT 0,
                stripe_session_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                report_path TEXT,
                notes TEXT
            );
        """)


init_db()


# ===== Landing Pages =====

@app.get("/", response_class=HTMLResponse)
async def landing():
    """Main marketing landing page."""
    return HTMLResponse(content=read_template("index.html"))


@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page():
    """Pricing page."""
    return HTMLResponse(content=read_template("index.html"))  # Same page, scrolls to pricing


@app.get("/docs", response_class=HTMLResponse)
async def docs_page():
    """Documentation page."""
    return HTMLResponse(content=read_template("index.html"))


# ===== Scan Request Flow =====

@app.get("/scan", response_class=HTMLResponse)
async def scan_request_form():
    """Scan request form."""
    return HTMLResponse(content=read_template("scan_request.html"))


class ScanRequest(BaseModel):
    email: str
    target: str
    scan_type: str = "quick"
    notes: Optional[str] = None


@app.post("/api/scan/request")
async def create_scan_request(scan_req: ScanRequest):
    """Create a new scan request."""
    scan_id = str(uuid.uuid4())[:8]
    
    pricing = {
        "quick": 9.99,
        "standard": 19.99,
        "aggressive": 49.99,
    }
    amount = pricing.get(scan_req.scan_type, 19.99)
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO scan_requests 
            (id, email, target, scan_type, amount, status, payment_status)
            VALUES (?, ?, ?, ?, ?, 'pending', 'unpaid')
        """, (scan_id, scan_req.email, scan_req.target, scan_req.scan_type, amount))
    
    return {
        "scan_id": scan_id,
        "amount": amount,
        "checkout_url": f"/checkout/{scan_id}",
    }


@app.get("/checkout/{scan_id}", response_class=HTMLResponse)
async def checkout_page(scan_id: str):
    """Checkout page for scan."""
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan request not found")
    
    # Replace placeholders in template
    html = read_template("checkout.html")
    html = html.replace("{{ scan.target }}", scan["target"])
    html = html.replace("{{ scan.scan_type }}", scan["scan_type"])
    html = html.replace("{{ scan.email }}", scan["email"])
    html = html.replace('{{ "%.2f" | format(scan.amount) }}', f'{scan["amount"]:.2f}')
    html = html.replace("{{ scan.id }}", scan["id"])
    
    return HTMLResponse(content=html)


@app.post("/api/checkout/create-session")
async def create_checkout_session(data: dict):
    """Create checkout session."""
    scan_id = data.get("scan_id")
    
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # In production, create Stripe session here
    return {
        "url": f"/payment/success?scan_id={scan_id}",
        "session_id": f"cs_test_{scan_id}",
    }


@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(scan_id: str):
    """Payment success page."""
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_requests SET payment_status = 'paid', status = 'queued' WHERE id = ?",
            (scan_id,),
        )
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    html = read_template("payment_success.html")
    html = html.replace("{{ scan.id }}", scan["id"])
    html = html.replace("{{ scan.target }}", scan["target"])
    html = html.replace("{{ scan.email }}", scan["email"])
    
    return HTMLResponse(content=html)


# ===== API Endpoints =====

@app.get("/api/stats")
async def get_marketing_stats():
    """Get marketing stats."""
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scan_requests").fetchone()[0]
        completed = conn.execute(
            "SELECT COUNT(*) FROM scan_requests WHERE status = 'completed'"
        ).fetchone()[0]
        revenue = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM scan_requests WHERE payment_status = 'paid'"
        ).fetchone()[0]
    
    return {
        "total_scans_requested": total_scans,
        "scans_completed": completed,
        "total_revenue": revenue,
    }


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Check scan status."""
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return dict(scan)
