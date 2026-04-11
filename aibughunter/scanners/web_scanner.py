"""Web vulnerability scanner module."""

import asyncio
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse, urljoin, quote

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class WebVulnerabilityScanner:
    """Scans web applications for security vulnerabilities."""
    
    def __init__(
        self,
        target: str,
        depth: str = "standard",
        auth: Optional[str] = None,
        excluded_paths: Optional[list[str]] = None,
        output_dir: str = "./reports",
    ):
        self.target = target.rstrip("/")
        self.depth = depth
        self.auth = auth
        self.excluded_paths = excluded_paths or []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings = []
        self.visited_urls = set()
        
        # Configure HTTP client
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if auth:
            headers["Authorization"] = auth if auth.startswith("Bearer") else f"Bearer {auth}"
        
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers=headers,
        )
    
    async def run_scan(self) -> list[dict]:
        """Run complete web vulnerability scan."""
        console.print(Panel(f"[bold blue]Web Vulnerability Scan: {self.target}[/bold blue]"))
        
        # Set crawl limits based on depth
        depth_config = {
            "quick": {"max_depth": 1, "max_pages": 25},
            "standard": {"max_depth": 2, "max_pages": 50},
            "aggressive": {"max_depth": 3, "max_pages": 150},
        }
        config = depth_config.get(self.depth, depth_config["standard"])

        # Phase 1: Crawl and discover
        console.print("\n[bold cyan]Phase 1: Crawling and discovering endpoints...[/bold cyan]")
        endpoints = await self._crawl(max_depth=config["max_depth"], max_pages=config["max_pages"])
        console.print(f"[green]✓[/green] Discovered {len(endpoints)} endpoints")
        
        # Phase 2: Test for vulnerabilities
        console.print("\n[bold cyan]Phase 2: Testing for vulnerabilities...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # XSS Testing
            task = progress.add_task("Testing for XSS vulnerabilities...", total=None)
            xss_findings = await self._test_xss(endpoints)
            self.findings.extend(xss_findings)
            progress.update(task, description=f"✓ XSS testing complete ({len(xss_findings)} findings)")
            
            # SQL Injection Testing
            task = progress.add_task("Testing for SQL injection...", total=None)
            sqli_findings = await self._test_sqli(endpoints)
            self.findings.extend(sqli_findings)
            progress.update(task, description=f"✓ SQLi testing complete ({len(sqli_findings)} findings)")
            
            # Security Headers
            task = progress.add_task("Checking security headers...", total=None)
            headers_findings = await self._check_security_headers()
            self.findings.extend(headers_findings)
            progress.update(task, description=f"✓ Security headers check complete ({len(headers_findings)} findings)")
            
            # Information Disclosure
            task = progress.add_task("Checking for information disclosure...", total=None)
            info_findings = await self._check_info_disclosure()
            self.findings.extend(info_findings)
            progress.update(task, description=f"✓ Info disclosure check complete ({len(info_findings)} findings)")
            
            # Cookie Security
            task = progress.add_task("Checking cookie security...", total=None)
            cookie_findings = await self._check_cookie_security()
            self.findings.extend(cookie_findings)
            progress.update(task, description=f"✓ Cookie security check complete ({len(cookie_findings)} findings)")
        
        # Save results
        self._save_results()
        
        console.print(Panel(
            f"[bold green]Scan Complete[/bold green]\n"
            f"Total findings: {len(self.findings)}\n"
            f"Critical: {len([f for f in self.findings if f.get('severity') == 'critical'])}\n"
            f"High: {len([f for f in self.findings if f.get('severity') == 'high'])}\n"
            f"Medium: {len([f for f in self.findings if f.get('severity') == 'medium'])}",
        ))
        
        return self.findings
    
    async def _crawl(self, max_depth: int = 3, max_pages: int = 100) -> list[dict]:
        """Crawl website to discover endpoints."""
        endpoints = []
        queue = [(self.target, 0)]
        pages_crawled = 0
        
        while queue and pages_crawled < max_pages:
            url, current_depth = queue.pop(0)
            
            if url in self.visited_urls:
                continue
            
            # Check depth
            if current_depth > max_depth:
                continue
            
            # Check excluded paths
            if any(excluded in url for excluded in self.excluded_paths):
                continue
            
            self.visited_urls.add(url)
            pages_crawled += 1
            
            try:
                response = await asyncio.wait_for(
                    self.client.get(url),
                    timeout=10.0,  # 10 second timeout per page
                )
                
                endpoints.append({
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "method": "GET",
                })
                
                # Only parse links if HTML and we haven't hit the page limit
                if "text/html" in response.headers.get("content-type", "") and pages_crawled < max_pages:
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        
                        # Strip fragments
                        full_url = full_url.split("#")[0]
                        
                        # Only follow same-domain links
                        if urlparse(full_url).netloc == urlparse(self.target).netloc:
                            if full_url not in self.visited_urls:
                                queue.append((full_url, current_depth + 1))
            
            except asyncio.TimeoutError:
                console.print(f"[yellow]⚠ Timeout crawling: {url}[/yellow]")
            except Exception as e:
                # Silently skip failed URLs
                pass
            
            # Rate limiting
            await asyncio.sleep(0.1)
        
        if pages_crawled >= max_pages:
            console.print(f"[yellow]⚠ Reached max pages limit ({max_pages}), stopping crawl[/yellow]")
        
        return endpoints
    
    async def _test_xss(self, endpoints: list[dict]) -> list[dict]:
        """Test for Cross-Site Scripting vulnerabilities."""
        findings = []
        
        # Find endpoints with query parameters
        param_endpoints = [ep for ep in endpoints if "?" in ep["url"]]
        
        for endpoint in param_endpoints[:20]:  # Limit testing
            url = endpoint["url"]
            
            # Test different XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                "javascript:alert(1)",
            ]
            
            parsed = urlparse(url)
            params = dict(q.split("=") for q in parsed.query.split("&") if "=" in q)
            
            for param_name in params.keys():
                for payload in xss_payloads:
                    # Create test URL with payload
                    test_params = params.copy()
                    test_params[param_name] = quote(payload)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url += "?" + "&".join(f"{k}={v}" for k, v in test_params.items())
                    
                    try:
                        response = await self.client.get(test_url)
                        
                        # Check if payload is reflected without proper encoding
                        if payload in response.text:
                            # Check if it's in a dangerous context
                            if not any(protect in response.text for protect in [
                                "Content-Security-Policy",
                                "X-XSS-Protection: 1",
                            ]):
                                findings.append({
                                    "id": f"XSS-{len(findings)+1:03d}",
                                    "type": "cross-site_scripting",
                                    "severity": "high",
                                    "title": f"Reflected XSS in {param_name} parameter",
                                    "description": f"The {param_name} parameter reflects user input without proper encoding.",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "target": self.target,
                                    "timestamp": datetime.now().isoformat(),
                                })
                                break  # Move to next parameter after finding
                    
                    except Exception:
                        pass
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        return findings
    
    async def _test_sqli(self, endpoints: list[dict]) -> list[dict]:
        """Test for SQL Injection vulnerabilities."""
        findings = []
        
        # Find endpoints with query parameters
        param_endpoints = [ep for ep in endpoints if "?" in ep["url"]]
        
        for endpoint in param_endpoints[:20]:
            url = endpoint["url"]
            
            # SQLi payloads
            sqli_payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' ORDER BY 1--",
                "1' AND 1=1--",
                "' OR 'x'='x",
            ]
            
            parsed = urlparse(url)
            params = dict(q.split("=") for q in parsed.query.split("&") if "=" in q)
            
            for param_name in params.keys():
                original_value = params[param_name]
                
                for payload in sqli_payloads:
                    test_params = params.copy()
                    test_params[param_name] = quote(payload)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url += "?" + "&".join(f"{k}={v}" for k, v in test_params.items())
                    
                    try:
                        response = await self.client.get(test_url)
                        
                        # Check for SQL errors in response
                        sql_errors = [
                            "SQL syntax",
                            "mysql_fetch",
                            "mysqli_query",
                            "pg_query",
                            "ORA-",
                            "SQLite3",
                            "Unclosed quotation mark",
                            "Invalid SQL statement",
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                findings.append({
                                    "id": f"SQLI-{len(findings)+1:03d}",
                                    "type": "sql_injection",
                                    "severity": "critical",
                                    "title": f"SQL Injection in {param_name} parameter",
                                    "description": f"The {param_name} parameter appears vulnerable to SQL injection.",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "error_found": error,
                                    "target": self.target,
                                    "timestamp": datetime.now().isoformat(),
                                })
                                break
                    
                    except Exception:
                        pass
                
                # Restore original value
                params[param_name] = original_value
            
            await asyncio.sleep(0.1)
        
        return findings
    
    async def _check_security_headers(self) -> list[dict]:
        """Check for missing or misconfigured security headers."""
        findings = []
        
        try:
            response = await self.client.get(self.target)
            headers = response.headers
            
            # Required security headers
            required_headers = {
                "Content-Security-Policy": {
                    "severity": "high",
                    "description": "Missing Content-Security-Policy header allows XSS attacks",
                },
                "X-Frame-Options": {
                    "severity": "medium",
                    "description": "Missing X-Frame-Options header allows clickjacking",
                },
                "X-Content-Type-Options": {
                    "severity": "medium",
                    "description": "Missing X-Content-Type-Options header allows MIME sniffing",
                },
                "Strict-Transport-Security": {
                    "severity": "high",
                    "description": "Missing HSTS header allows protocol downgrade attacks",
                },
                "X-XSS-Protection": {
                    "severity": "low",
                    "description": "Missing X-XSS-Protection header",
                },
                "Referrer-Policy": {
                    "severity": "low",
                    "description": "Missing Referrer-Policy header may leak sensitive URLs",
                },
                "Permissions-Policy": {
                    "severity": "low",
                    "description": "Missing Permissions-Policy header allows access to browser features",
                },
            }
            
            for header, info in required_headers.items():
                if header not in headers:
                    findings.append({
                        "id": f"HEADER-{len(findings)+1:03d}",
                        "type": "missing_security_header",
                        "severity": info["severity"],
                        "title": f"Missing {header} header",
                        "description": info["description"],
                        "url": self.target,
                        "header": header,
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                    })
                elif header == "X-Frame-Options" and headers[header].upper() not in ["DENY", "SAMEORIGIN"]:
                    findings.append({
                        "id": f"HEADER-{len(findings)+1:03d}",
                        "type": "misconfigured_security_header",
                        "severity": "medium",
                        "title": f"Misconfigured {header} header",
                        "description": f"X-Frame-Options has unsafe value: {headers[header]}",
                        "url": self.target,
                        "header": header,
                        "value": headers[header],
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                    })
        
        except Exception as e:
            console.print(f"[yellow]⚠ Security headers check failed: {e}[/yellow]")
        
        return findings
    
    async def _check_info_disclosure(self) -> list[dict]:
        """Check for information disclosure vulnerabilities."""
        findings = []
        
        # Check common sensitive files
        sensitive_files = {
            "/robots.txt": "low",
            "/sitemap.xml": "low",
            "/.env": "critical",
            "/.git/config": "high",
            "/.htaccess": "medium",
            "/wp-config.php": "critical",
            "/config.php": "critical",
            "/database.yml": "high",
            "/.DS_Store": "medium",
            "/server-status": "high",
            "/phpinfo.php": "high",
            "/info.php": "high",
            "/test.php": "medium",
            "/debug": "medium",
            "/.well-known/security.txt": "info",
        }
        
        for file_path, severity in sensitive_files.items():
            try:
                url = f"{self.target}{file_path}"
                response = await self.client.get(url)
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Don't flag expected files like robots.txt and security.txt as high severity
                    if file_path in ["/robots.txt", "/.well-known/security.txt"]:
                        severity = "info"
                    
                    findings.append({
                        "id": f"INFO-{len(findings)+1:03d}",
                        "type": "information_disclosure",
                        "severity": severity,
                        "title": f"Sensitive file accessible: {file_path}",
                        "description": f"The file {file_path} is publicly accessible and may contain sensitive information.",
                        "url": url,
                        "file": file_path,
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                    })
            
            except Exception:
                pass
            
            await asyncio.sleep(0.1)
        
        return findings
    
    async def _check_cookie_security(self) -> list[dict]:
        """Check for cookie security issues."""
        findings = []
        
        try:
            response = await self.client.get(self.target)
            cookies = response.cookies
            
            if cookies:
                for cookie_name, cookie_value in cookies.items():
                    # Check for Secure flag
                    cookie_header = response.headers.get("set-cookie", "")
                    
                    if "Secure" not in cookie_header and self.target.startswith("https"):
                        findings.append({
                            "id": f"COOKIE-{len(findings)+1:03d}",
                            "type": "insecure_cookie",
                            "severity": "medium",
                            "title": f"Cookie without Secure flag: {cookie_name}",
                            "description": f"The cookie {cookie_name} is missing the Secure flag over HTTPS connection.",
                            "url": self.target,
                            "cookie": cookie_name,
                            "target": self.target,
                            "timestamp": datetime.now().isoformat(),
                        })
                    
                    # Check for HttpOnly flag on session cookies
                    if "session" in cookie_name.lower() and "HttpOnly" not in cookie_header:
                        findings.append({
                            "id": f"COOKIE-{len(findings)+1:03d}",
                            "type": "cookie_no_httponly",
                            "severity": "medium",
                            "title": f"Session cookie without HttpOnly flag: {cookie_name}",
                            "description": f"The session cookie {cookie_name} is missing the HttpOnly flag.",
                            "url": self.target,
                            "cookie": cookie_name,
                            "target": self.target,
                            "timestamp": datetime.now().isoformat(),
                        })
        
        except Exception as e:
            console.print(f"[yellow]⚠ Cookie security check failed: {e}[/yellow]")
        
        return findings
    
    def _save_results(self):
        """Save scan results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"web_scan_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "scan_type": "web_vulnerability",
                "depth": self.depth,
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "findings": self.findings,
            }, f, indent=2)
        
        console.print(f"\n[green]✓[/green] Results saved to {output_file}")
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
