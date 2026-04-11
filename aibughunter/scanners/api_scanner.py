"""API security scanner module."""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

import httpx
from rich.console import Console

console = Console()


class APIScanner:
    """Scans APIs for security vulnerabilities."""
    
    def __init__(
        self,
        target: str,
        api_type: str = "rest",
        auth: Optional[str] = None,
        output_dir: str = "./reports",
    ):
        self.target = target
        self.api_type = api_type
        self.auth = auth
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings = []
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers=self._build_headers(),
        )
    
    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        if self.auth:
            headers["Authorization"] = self.auth
        return headers
    
    async def run_scan(self) -> list[dict]:
        """Run API security scan."""
        console.print(f"[bold blue]API Scan: {self.target} ({self.api_type})[/bold blue]")
        
        if self.api_type == "rest":
            await self._scan_rest_api()
        elif self.api_type == "graphql":
            await self._scan_graphql()
        
        self._save_results()
        return self.findings
    
    async def _scan_rest_api(self):
        """Scan REST API for common vulnerabilities."""
        console.print("[cyan]Testing REST API security...[/cyan]")
        
        # Check for common security issues
        await self._check_api_documentation()
        await self._check_http_methods()
        await self._check_authentication()
    
    async def _scan_graphql(self):
        """Scan GraphQL API for vulnerabilities."""
        console.print("[cyan]Testing GraphQL security...[/cyan]")
        
        # Test for introspection
        await self._test_graphql_introspection()
    
    async def _check_api_documentation(self):
        """Check if API documentation is exposed."""
        paths = ["/swagger.json", "/api-docs", "/openapi.json", "/graphql", "/api/v1/docs"]
        
        for path in paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    self.findings.append({
                        "id": f"API-DOC-{len(self.findings)+1:03d}",
                        "type": "api_documentation_exposed",
                        "severity": "medium",
                        "title": f"API documentation exposed at {path}",
                        "description": "API documentation is publicly accessible.",
                        "url": url,
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                    })
            except Exception:
                pass
    
    async def _check_http_methods(self):
        """Check for dangerous HTTP methods."""
        methods = ["OPTIONS", "TRACE", "TRACK", "PUT", "DELETE"]
        
        for method in methods:
            try:
                response = await self.client.request(method, self.target)
                
                if response.status_code in [200, 204]:
                    self.findings.append({
                        "id": f"API-METHOD-{len(self.findings)+1:03d}",
                        "type": "dangerous_http_method",
                        "severity": "medium",
                        "title": f"HTTP {method} method enabled",
                        "description": f"The {method} method is enabled and may allow information disclosure or attacks.",
                        "url": self.target,
                        "method": method,
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                    })
            except Exception:
                pass
    
    async def _check_authentication(self):
        """Check API authentication mechanisms."""
        # Test without authentication
        try:
            response = await httpx.AsyncClient().get(
                self.target,
                headers={"Accept": "application/json"},
                timeout=10.0,
            )
            
            if response.status_code == 200:
                self.findings.append({
                    "id": f"API-AUTH-{len(self.findings)+1:03d}",
                    "type": "no_authentication_required",
                    "severity": "high",
                    "title": "API endpoint accessible without authentication",
                    "description": "The API endpoint returns data without requiring authentication.",
                    "url": self.target,
                    "target": self.target,
                    "timestamp": datetime.now().isoformat(),
                })
        except Exception:
            pass
    
    async def _test_graphql_introspection(self):
        """Test if GraphQL introspection is enabled."""
        introspection_query = """
        query {
          __schema {
            types {
              name
              fields {
                name
              }
            }
          }
        }
        """
        
        try:
            response = await self.client.post(
                self.target,
                json={"query": introspection_query},
            )
            
            if response.status_code == 200 and "__schema" in response.text:
                self.findings.append({
                    "id": f"API-GQL-{len(self.findings)+1:03d}",
                    "type": "graphql_introspection_enabled",
                    "severity": "medium",
                    "title": "GraphQL introspection enabled",
                    "description": "GraphQL introspection is enabled, exposing the full schema.",
                    "url": self.target,
                    "target": self.target,
                    "timestamp": datetime.now().isoformat(),
                })
        except Exception:
            pass
    
    def _save_results(self):
        """Save scan results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"api_scan_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "api_type": self.api_type,
                "timestamp": datetime.now().isoformat(),
                "findings": self.findings,
            }, f, indent=2)
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
