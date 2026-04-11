"""
AI Bug Hunter - SaaS Platform with User Dashboard

Full SPA (Single Page Application) with:
- User authentication
- Scan request & payment flow
- Dashboard with scan history
- Report downloads
- Stripe integration
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Optional
import os
import uuid
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
import jwt  # PyJWT
import json

app = FastAPI(
    title="AI Bug Hunter SaaS",
    description="Automated Bug Bounty Hunting Platform",
    version="2.0.0",
)

# CORS for SPA
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY", "")
BASE_URL = os.getenv("BASE_URL", "https://aibughunter-marketing.fly.dev")

# Database
db_path = Path(__file__).parent.parent.parent / "data" / "saas.db"
db_path.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_db():
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                plan TEXT DEFAULT 'free',
                scans_used INTEGER DEFAULT 0,
                scans_limit INTEGER DEFAULT 1,
                stripe_customer_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            );
            
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'standard',
                status TEXT DEFAULT 'pending',
                payment_status TEXT DEFAULT 'unpaid',
                amount REAL DEFAULT 0,
                stripe_session_id TEXT,
                stripe_payment_id TEXT,
                progress INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                completed_at TEXT,
                report_path TEXT,
                findings_count INTEGER DEFAULT 0,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                scan_id TEXT,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'usd',
                status TEXT DEFAULT 'pending',
                stripe_payment_id TEXT,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                findings_json TEXT,
                summary_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
        """)


init_db()


# ===== Auth Helpers =====

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${pw_hash}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, pw_hash = stored.split("$")
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == pw_hash
    except Exception:
        return False


def create_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ===== Data Models =====

class UserRegister(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "standard"  # quick, standard, aggressive
    notes: Optional[str] = None


class PlanUpgrade(BaseModel):
    plan: str  # pro, enterprise


# ===== Auth Endpoints =====

@app.post("/api/auth/register")
async def register(data: UserRegister):
    """Register new user."""
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(data.password)
    
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)",
                (user_id, data.email, pw_hash, data.name),
            )
        
        token = create_token(user_id)
        
        return {
            "token": token,
            "user": {
                "id": user_id,
                "email": data.email,
                "name": data.name,
                "plan": "free",
                "scans_limit": 1,
            },
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")


@app.post("/api/auth/login")
async def login(data: UserLogin):
    """Login user."""
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (data.email,),
        ).fetchone()
    
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Update last login
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), user["id"]),
        )
    
    token = create_token(user["id"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "plan": user["plan"],
            "scans_used": user["scans_used"],
            "scans_limit": user["scans_limit"],
        },
    }


@app.get("/api/auth/me")
async def get_user(authorization: str = ""):
    """Get current user."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        user = conn.execute(
            "SELECT id, email, name, plan, scans_used, scans_limit, created_at FROM users WHERE id = ?",
            (payload["user_id"],),
        ).fetchone()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return dict(user)


# ===== Scan Endpoints =====

@app.post("/api/scans")
async def create_scan(
    scan_req: ScanRequest,
    authorization: str = "",
):
    """Request a new scan."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (payload["user_id"],),
        ).fetchone()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check scan limit
    if user["scans_used"] >= user["scans_limit"]:
        raise HTTPException(
            status_code=402,
            detail="Scan limit reached. Please upgrade your plan.",
        )
    
    # Pricing
    pricing = {"quick": 9.99, "standard": 19.99, "aggressive": 49.99}
    amount = pricing.get(scan_req.scan_type, 19.99)
    
    # Free users get first scan free
    if user["plan"] == "free" and user["scans_used"] == 0:
        amount = 0
    
    scan_id = str(uuid.uuid4())[:8]
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO scans 
            (id, user_id, target, scan_type, amount, status, payment_status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            user["id"],
            scan_req.target,
            scan_req.scan_type,
            amount,
            "pending" if amount > 0 else "queued",
            "paid" if amount == 0 else "unpaid",
            scan_req.notes,
        ))
    
    return {
        "scan_id": scan_id,
        "amount": amount,
        "status": "queued" if amount == 0 else "pending",
        "checkout_url": f"/api/payments/checkout?scan_id={scan_id}" if amount > 0 else None,
    }


@app.get("/api/scans")
async def list_scans(authorization: str = ""):
    """List user's scans."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        scans = conn.execute(
            """SELECT s.*, 
               CASE WHEN sr.findings_json IS NOT NULL 
                    THEN json_extract(sr.findings_json, '$.total_findings') 
                    ELSE 0 END as findings_count
             FROM scans s
             LEFT JOIN scan_results sr ON s.id = sr.scan_id
             WHERE s.user_id = ?
             ORDER BY s.created_at DESC""",
            (payload["user_id"],),
        ).fetchall()
    
    return [dict(s) for s in scans]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, authorization: str = ""):
    """Get scan details."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, payload["user_id"]),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = dict(scan)
    
    # Include findings if available
    with get_db() as conn:
        scan_result = conn.execute(
            "SELECT * FROM scan_results WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    
    if scan_result:
        result["findings"] = json.loads(scan_result["findings_json"])
        result["summary"] = json.loads(scan_result["summary_json"])
    
    return result


@app.get("/api/scans/{scan_id}/report")
async def download_report(scan_id: str, authorization: str = ""):
    """Download scan report."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND user_id = ? AND status = 'completed'",
            (scan_id, payload["user_id"]),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Report not available")
    
    with get_db() as conn:
        scan_result = conn.execute(
            "SELECT * FROM scan_results WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    
    if not scan_result:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return JSONResponse(content=json.loads(scan_result["findings_json"]))


# ===== Payment Endpoints =====

@app.get("/api/payments/checkout")
async def create_checkout_session(scan_id: str, authorization: str = ""):
    """Create Stripe checkout session."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, payload["user_id"]),
        ).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # In production: Create Stripe Checkout Session
    # For now, simulate successful payment
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET payment_status = 'paid', status = 'queued' WHERE id = ?",
            (scan_id,),
        )
        conn.execute("""
            INSERT INTO payments 
            (id, user_id, scan_id, amount, status, description)
            VALUES (?, ?, ?, ?, 'completed', ?)
        """, (
            str(uuid.uuid4()),
            payload["user_id"],
            scan_id,
            scan["amount"],
            f"{scan['scan_type'].title()} scan for {scan['target']}",
        ))
    
    return {
        "status": "success",
        "message": "Payment processed (demo mode)",
        "scan_id": scan_id,
    }


# ===== Plans =====

@app.get("/api/plans")
async def get_plans():
    """Get available subscription plans."""
    return {
        "plans": [
            {
                "id": "free",
                "name": "Free Trial",
                "price": 0,
                "scans_limit": 1,
                "features": [
                    "1 free scan",
                    "Basic vulnerability scan",
                    "Markdown report",
                    "48-hour turnaround",
                ],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": 49,
                "scans_limit": 10,
                "features": [
                    "10 scans/month",
                    "Full vulnerability scan",
                    "HTML + Markdown reports",
                    "AI-powered analysis",
                    "24-hour turnaround",
                    "Priority support",
                    "API access",
                ],
                "popular": True,
            },
            {
                "id": "enterprise",
                "name": "Enterprise",
                "price": 199,
                "scans_limit": -1,  # Unlimited
                "features": [
                    "Unlimited scans",
                    "Everything in Pro",
                    "Kali Linux tools integration",
                    "Exploitation testing",
                    "Custom POC generation",
                    "12-hour turnaround",
                    "Dedicated support",
                    "Team features",
                    "Custom reports",
                ],
            },
        ],
    }


@app.post("/api/plans/upgrade")
async def upgrade_plan(data: PlanUpgrade, authorization: str = ""):
    """Upgrade user's subscription plan."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    plan_limits = {
        "pro": 10,
        "enterprise": -1,
    }
    
    limit = plan_limits.get(data.plan, 1)
    
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET plan = ?, scans_limit = ? WHERE id = ?",
            (data.plan, limit, payload["user_id"]),
        )
    
    return {
        "status": "success",
        "plan": data.plan,
        "scans_limit": limit,
        "message": "Plan upgraded successfully (demo mode)",
    }


# ===== Dashboard Stats =====

@app.get("/api/dashboard/stats")
async def dashboard_stats(authorization: str = ""):
    """Get dashboard statistics."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (payload["user_id"],),
        ).fetchone()
        
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ?",
            (payload["user_id"],),
        ).fetchone()[0]
        
        completed_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'completed'",
            (payload["user_id"],),
        ).fetchone()[0]
        
        total_findings = conn.execute(
            """SELECT COALESCE(SUM(
                CASE WHEN sr.findings_json IS NOT NULL 
                     THEN json_extract(sr.findings_json, '$.total_findings') 
                     ELSE 0 END
            ), 0)
            FROM scans s
            LEFT JOIN scan_results sr ON s.id = sr.scan_id
            WHERE s.user_id = ?""",
            (payload["user_id"],),
        ).fetchone()[0]
    
    return {
        "user": {
            "email": user["email"],
            "name": user["name"],
            "plan": user["plan"],
            "scans_used": user["scans_used"],
            "scans_limit": user["scans_limit"],
        },
        "stats": {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
        },
    }


# ===== SPA Serving =====

@app.get("/", response_class=HTMLResponse)
async def serve_spa():
    """Serve SPA."""
    spa_file = Path(__file__).parent / "spa" / "index.html"
    if spa_file.exists():
        return HTMLResponse(content=spa_file.read_text())
    return HTMLResponse(content="<h1>SPA not found</h1>")


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_spa_catchall():
    """Catch-all for SPA routes."""
    spa_file = Path(__file__).parent / "spa" / "index.html"
    if spa_file.exists():
        return HTMLResponse(content=spa_file.read_text())
    return HTMLResponse(content="<h1>Not found</h1>", status_code=404)
