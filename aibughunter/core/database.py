"""SQLite database for persistent storage of findings, targets, and scan history."""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from contextlib import contextmanager


class Database:
    """SQLite database manager for AI Bug Hunter."""
    
    def __init__(self, db_path: str = "./data/aibughunter.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    @contextmanager
    def connection(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema."""
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_type TEXT DEFAULT 'web',
                    status TEXT DEFAULT 'completed',
                    started_at TEXT,
                    completed_at TEXT,
                    duration_seconds REAL,
                    total_findings INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    type TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    url TEXT,
                    parameter TEXT,
                    target TEXT,
                    payload TEXT,
                    impact TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'new',
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
                
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    scope_type TEXT DEFAULT 'in',
                    program TEXT DEFAULT 'default',
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    platform TEXT,
                    url TEXT,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS tool_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT,
                    command TEXT,
                    target TEXT,
                    status TEXT,
                    output_file TEXT,
                    executed_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            """)
    
    # ===== Scans =====
    
    def create_scan(self, scan_id: str, target: str, scan_type: str = "web") -> str:
        """Create a new scan record."""
        with self.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scans (id, target, scan_type, started_at) VALUES (?, ?, ?, ?)",
                (scan_id, target, scan_type, datetime.now().isoformat()),
            )
        return scan_id
    
    def complete_scan(self, scan_id: str, duration: float, total_findings: int):
        """Mark scan as completed."""
        with self.connection() as conn:
            conn.execute(
                "UPDATE scans SET status = 'completed', completed_at = ?, duration_seconds = ?, total_findings = ? WHERE id = ?",
                (datetime.now().isoformat(), duration, total_findings, scan_id),
            )
    
    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Get scan by ID."""
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None
    
    def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scans."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    
    # ===== Findings =====
    
    def save_finding(self, finding: dict, scan_id: Optional[str] = None) -> str:
        """Save a vulnerability finding."""
        finding_id = finding.get("id", f"VULN-{datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        with self.connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO findings 
                (id, scan_id, type, severity, title, description, url, parameter, target, 
                 payload, impact, remediation, status, raw_data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                scan_id or finding.get("scan_id"),
                finding.get("type"),
                finding.get("severity", "info"),
                finding.get("title"),
                finding.get("description"),
                finding.get("url"),
                finding.get("parameter"),
                finding.get("target"),
                finding.get("payload"),
                finding.get("impact"),
                finding.get("remediation"),
                finding.get("status", "new"),
                json.dumps(finding),
                finding.get("timestamp", datetime.now().isoformat()),
            ))
        
        return finding_id
    
    def save_findings_batch(self, findings: list[dict], scan_id: Optional[str] = None):
        """Save multiple findings at once."""
        with self.connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO findings 
                (id, scan_id, type, severity, title, description, url, parameter, target, 
                 payload, impact, remediation, status, raw_data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    f.get("id", f"VULN-{i}-{datetime.now().strftime('%H%M%S')}"),
                    scan_id or f.get("scan_id"),
                    f.get("type"),
                    f.get("severity", "info"),
                    f.get("title"),
                    f.get("description"),
                    f.get("url"),
                    f.get("parameter"),
                    f.get("target"),
                    f.get("payload"),
                    f.get("impact"),
                    f.get("remediation"),
                    f.get("status", "new"),
                    json.dumps(f),
                    f.get("timestamp", datetime.now().isoformat()),
                )
                for i, f in enumerate(findings)
            ])
    
    def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query findings with filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        
        if status:
            query += " AND status = ?"
            params.append(status.lower())
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC"
        query += " LIMIT ?"
        params.append(limit)
        
        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    
    def update_finding_status(self, finding_id: str, status: str):
        """Update finding status (new, triaged, reported, resolved)."""
        with self.connection() as conn:
            conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status.lower(), finding_id),
            )
    
    def get_stats(self) -> dict:
        """Get vulnerability statistics."""
        with self.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
            ).fetchall()
            by_status = conn.execute(
                "SELECT status, COUNT(*) as count FROM findings GROUP BY status"
            ).fetchall()
            
            return {
                "total_findings": total,
                "by_severity": {dict(r)["severity"]: dict(r)["count"] for r in by_severity},
                "by_status": {dict(r)["status"]: dict(r)["count"] for r in by_status},
            }
    
    # ===== Targets =====
    
    def add_target(self, target: str, scope_type: str = "in", program: str = "default", notes: Optional[str] = None):
        """Add target to scope."""
        with self.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO targets (target, scope_type, program, notes) VALUES (?, ?, ?, ?)",
                (target, scope_type, program, notes),
            )
    
    def remove_target(self, target: str):
        """Remove target from scope."""
        with self.connection() as conn:
            conn.execute("DELETE FROM targets WHERE target = ?", (target,))
    
    def list_targets(
        self,
        program: Optional[str] = None,
        scope_type: Optional[str] = None,
    ) -> list[dict]:
        """List targets with filters."""
        query = "SELECT * FROM targets WHERE 1=1"
        params = []
        
        if program:
            query += " AND program = ?"
            params.append(program)
        
        if scope_type:
            query += " AND scope_type = ?"
            params.append(scope_type)
        
        query += " ORDER BY created_at DESC"
        
        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT scope_type FROM targets WHERE ? LIKE '%' || target OR target = ?",
                (target, target),
            ).fetchone()
            
            if row:
                return dict(row)["scope_type"] == "in"
            return True  # Default to in-scope if not found
    
    # ===== Programs =====
    
    def add_program(self, name: str, platform: Optional[str] = None, url: Optional[str] = None):
        """Add bug bounty program."""
        with self.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO programs (name, platform, url) VALUES (?, ?, ?)",
                (name, platform, url),
            )
    
    def list_programs(self) -> list[dict]:
        """List all programs."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT p.*, COUNT(t.id) as target_count 
                FROM programs p 
                LEFT JOIN targets t ON p.name = t.program 
                GROUP BY p.name
                ORDER BY p.name
            """).fetchall()
            return [dict(r) for r in rows]
    
    # ===== Tool Usage =====
    
    def log_tool_usage(self, tool_name: str, command: str, target: str, status: str, output_file: Optional[str] = None):
        """Log tool execution."""
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO tool_usage (tool_name, command, target, status, output_file) VALUES (?, ?, ?, ?, ?)",
                (tool_name, command, target, status, output_file),
            )
    
    def get_tool_stats(self) -> dict:
        """Get tool usage statistics."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT tool_name, COUNT(*) as executions FROM tool_usage GROUP BY tool_name ORDER BY executions DESC"
            ).fetchall()
            return {dict(r)["tool_name"]: dict(r)["executions"] for r in rows}
