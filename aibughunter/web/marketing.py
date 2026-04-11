"""Marketing landing page with payment integration."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import os
import json
import uuid
from datetime import datetime
from pathlib import Path

app = FastAPI(
    title="AI Bug Hunter",
    description="AI-Powered Bug Bounty Hunting Platform",
    version="1.0.0",
)

# Templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Database for scan requests and payments (SQLite)
import sqlite3
from contextlib import contextmanager

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
            
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                plan TEXT NOT NULL,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                status TEXT DEFAULT 'active',
                scans_used INTEGER DEFAULT 0,
                scans_limit INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT
            );
            
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'usd',
                status TEXT DEFAULT 'pending',
                stripe_payment_id TEXT,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)


init_db()


# ===== Landing Pages =====

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """Main marketing landing page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/pricing", response_class=HTMLResponse)
def pricing_page(request: Request):
    """Pricing page."""
    return templates.TemplateResponse("pricing.html", {"request": request})


@app.get("/docs", response_class=HTMLResponse)
def docs_page(request: Request):
    """Documentation page."""
    return templates.TemplateResponse("docs.html", {"request": request})


# ===== Scan Request Flow =====

@app.get("/scan", response_class=HTMLResponse)
def scan_request_form(request: Request):
    """Scan request form."""
    return templates.TemplateResponse("scan_request.html", {
        "request": request,
        "stripe_key": os.getenv("STRIPE_PUBLISHABLE_KEY", ""),
    })


class ScanRequest(BaseModel):
    email: str
    target: str
    scan_type: str = "quick"  # quick, standard, aggressive
    notes: Optional[str] = None


@app.post("/api/scan/request")
def create_scan_request(scan_req: ScanRequest):
    """Create a new scan request."""
    scan_id = str(uuid.uuid4())[:8]
    
    # Determine price
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
def checkout_page(request: Request, scan_id: str):
    """Checkout page for scan."""
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan request not found")
    
    return templates.TemplateResponse("checkout.html", {
        "request": request,
        "scan": dict(scan),
        "stripe_key": os.getenv("STRIPE_PUBLISHABLE_KEY", ""),
    })


@app.post("/api/checkout/create-session")
def create_checkout_session(data: dict):
    """Create Stripe checkout session."""
    scan_id = data.get("scan_id")
    
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # In production, create Stripe session here
    # For now, return mock checkout URL
    return {
        "url": f"/payment/success?scan_id={scan_id}",
        "session_id": f"cs_test_{scan_id}",
    }


@app.get("/payment/success", response_class=HTMLResponse)
def payment_success(request: Request, scan_id: str):
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
    
    return templates.TemplateResponse("payment_success.html", {
        "request": request,
        "scan": dict(scan) if scan else {},
    })


# ===== API Endpoints =====

@app.get("/api/stats")
def get_marketing_stats():
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
def get_scan_status(scan_id: str):
    """Check scan status."""
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scan_requests WHERE id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return dict(scan)


# ===== Admin Dashboard =====

@app.get("/admin/scans", response_class=HTMLResponse)
def admin_scans(request: Request):
    """Admin view of all scan requests."""
    with get_db() as conn:
        scans = conn.execute(
            "SELECT * FROM scan_requests ORDER BY created_at DESC"
        ).fetchall()
    
    return templates.TemplateResponse("admin_scans.html", {
        "request": request,
        "scans": [dict(s) for s in scans],
    })


# ===== Static Files =====

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
