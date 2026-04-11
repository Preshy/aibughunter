"""Reconnaissance scanner module."""

import asyncio
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

import httpx
import dns.resolver
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


class ReconScanner:
    """Performs reconnaissance and information gathering."""
    
    def __init__(self, target: str, output_dir: str = "./recon"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        )
    
    async def enumerate_subdomains(self, method: str = "passive", wordlist: Optional[str] = None) -> list[str]:
        """Enumerate subdomains using various techniques."""
        subdomains = set()
        
        # Passive enumeration via DNS
        if method in ["passive", "all"]:
            console.print("[blue]  ├─ Passive DNS enumeration...[/blue]")
            passive_subs = await self._passive_dns()
            subdomains.update(passive_subs)
            console.print(f"[green]  └─ Found {len(passive_subs)} subdomains via passive DNS[/green]")
        
        # Active brute force
        if method in ["brute-force", "all"]:
            console.print("[blue]  ├─ Brute-force subdomain enumeration...[/blue]")
            bruteforce_subs = await self._bruteforce_subdomains(wordlist)
            subdomains.update(bruteforce_subs)
            console.print(f"[green]  └─ Found {len(bruteforce_subs)} subdomains via brute-force[/green]")
        
        # Save results
        results = sorted(subdomains)
        output_file = self.output_dir / "subdomains.json"
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "subdomains": results,
                "timestamp": datetime.now().isoformat(),
            }, f, indent=2)
        
        return results
    
    async def _passive_dns(self) -> list[str]:
        """Perform passive DNS enumeration."""
        subdomains = []
        
        # Try DNS resolution for common subdomains
        common_subs = [
            "www", "api", "dev", "staging", "test", "admin", "mail",
            "ftp", "smtp", "pop", "imap", "vpn", "portal", "app",
            "dashboard", "cdn", "static", "media", "docs", "blog",
            "support", "help", "docs", "status", "auth", "login",
            "sso", "oauth", "api-v1", "api-v2", "graphql", "ws",
        ]
        
        tasks = []
        for sub in common_subs:
            domain = f"{sub}.{self.target}"
            tasks.append(self._resolve_dns(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                subdomains.append(result)
        
        return subdomains
    
    async def _resolve_dns(self, domain: str) -> Optional[str]:
        """Resolve DNS for a subdomain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = resolver.resolve(domain, "A")
            if answers:
                return domain
        except Exception:
            pass
        return None
    
    async def _bruteforce_subdomains(self, wordlist: Optional[str] = None) -> list[str]:
        """Brute-force subdomains using a wordlist."""
        # For now, use built-in list. Will support custom wordlists later.
        return await self._passive_dns()
    
    async def analyze_techstack(self, detailed: bool = False) -> dict:
        """Analyze technologies used by the target."""
        tech_stack = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "technologies": {},
        }
        
        try:
            url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            response = await self.client.get(url)
            
            # Analyze headers
            tech_stack["technologies"]["headers"] = self._analyze_headers(response.headers)
            
            # Analyze HTML content
            tech_stack["technologies"]["content"] = self._analyze_content(response.text)
            
            # Analyze cookies
            tech_stack["technologies"]["cookies"] = self._analyze_cookies(response.headers.get("set-cookie", ""))
            
            # Deep analysis if requested
            if detailed:
                tech_stack["technologies"]["detailed"] = await self._deep_analysis(response.text, url)
            
        except Exception as e:
            console.print(f"[yellow]  ⚠ Tech analysis failed: {e}[/yellow]")
        
        # Save results
        output_file = self.output_dir / "techstack.json"
        with open(output_file, "w") as f:
            json.dump(tech_stack, f, indent=2)
        
        return tech_stack
    
    def _analyze_headers(self, headers: dict) -> dict:
        """Analyze HTTP headers for technology indicators."""
        technologies = {}
        
        header_map = {
            "x-powered-by": "backend",
            "server": "webserver",
            "x-aspnet-version": "aspnet",
            "x-generator": "cms",
            "x-drupal-cache": "drupal",
            "x-varnish": "varnish",
            "x-cdn": "cdn",
        }
        
        for header, tech in header_map.items():
            if header in headers:
                technologies[tech] = headers[header]
        
        return technologies
    
    def _analyze_content(self, content: str) -> dict:
        """Analyze HTML content for technology indicators."""
        technologies = {}
        
        # Common technology patterns
        patterns = {
            "wordpress": [r"wp-content", r"wp-includes", r"wp-json"],
            "react": [r"react", r"__react"],
            "angular": [r"ng-", r"angular"],
            "vue": [r"vue", r"__vue__"],
            "jquery": [r"jquery"],
            "bootstrap": [r"bootstrap"],
            "laravel": [r"laravel"],
            "django": [r"django"],
            "rails": [r"rails", r"csrf-param.*authenticity"],
        }
        
        for tech, pats in patterns.items():
            for pat in pats:
                if re.search(pat, content, re.IGNORECASE):
                    technologies[tech] = True
                    break
        
        return technologies
    
    def _analyze_cookies(self, cookies: str) -> dict:
        """Analyze cookies for technology indicators."""
        technologies = {}
        
        cookie_map = {
            "wordpress": "wp-",
            "laravel": "laravel_session",
            "django": "csrftoken",
            "rails": "_session",
            "php": "PHPSESSID",
            "aspnet": "ASP.NET_SessionId",
        }
        
        for tech, pattern in cookie_map.items():
            if pattern in cookies:
                technologies[tech] = True
        
        return technologies
    
    async def _deep_analysis(self, content: str, url: str) -> dict:
        """Perform deep technology analysis."""
        details = {}
        
        # Check for common files
        common_files = {
            "robots.txt": "/robots.txt",
            "sitemap.xml": "/sitemap.xml",
            "security.txt": "/.well-known/security.txt",
            "humans.txt": "/humans.txt",
        }
        
        for name, path in common_files.items():
            try:
                response = await self.client.get(f"{url.rstrip('/')}{path}")
                if response.status_code == 200:
                    details[name] = "exists"
            except Exception:
                pass
        
        return details
    
    async def discover_endpoints(self, crawl: bool = True, js_analysis: bool = True) -> list[dict]:
        """Discover endpoints and URLs."""
        endpoints = []
        
        try:
            url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            
            # Crawl the site
            if crawl:
                console.print("[blue]  ├─ Crawling for endpoints...[/blue]")
                crawled = await self._crawl(url, max_depth=2)
                endpoints.extend(crawled)
                console.print(f"[green]  └─ Found {len(crawled)} endpoints via crawling[/green]")
            
            # JavaScript analysis
            if js_analysis:
                console.print("[blue]  ├─ Analyzing JavaScript files...[/blue]")
                js_endpoints = await self._analyze_javascript(url)
                endpoints.extend(js_endpoints)
                console.print(f"[green]  └─ Found {len(js_endpoints)} endpoints via JS analysis[/green]")
            
        except Exception as e:
            console.print(f"[yellow]  ⚠ Endpoint discovery failed: {e}[/yellow]")
        
        # Save results
        output_file = self.output_dir / "endpoints.json"
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "endpoints": endpoints,
                "timestamp": datetime.now().isoformat(),
            }, f, indent=2)
        
        return endpoints
    
    async def _crawl(self, url: str, max_depth: int = 2) -> list[dict]:
        """Crawl website to discover endpoints."""
        visited = set()
        discovered = []
        
        async def _crawl_recursive(current_url: str, depth: int):
            if depth > max_depth or current_url in visited:
                return
            
            visited.add(current_url)
            
            try:
                response = await self.client.get(current_url)
                
                # Record endpoint
                discovered.append({
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "method": "GET",
                })
                
                # Parse links if HTML
                if "text/html" in response.headers.get("content-type", ""):
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        if href.startswith(("http", "/")):
                            if href.startswith("/"):
                                base = str(response.url).split("/")[2]
                                href = f"https://{base}{href}"
                            
                            if self.target in href:
                                await _crawl_recursive(href, depth + 1)
            
            except Exception:
                pass
        
        await _crawl_recursive(url, 0)
        return discovered
    
    async def _analyze_javascript(self, base_url: str) -> list[dict]:
        """Analyze JavaScript files for endpoints."""
        endpoints = []
        
        try:
            response = await self.client.get(base_url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Find JS files
            js_files = []
            for script in soup.find_all("script", src=True):
                js_files.append(script["src"])
            
            # Analyze each JS file for endpoints
            for js_url in js_files[:10]:  # Limit to 10 files
                if not js_url.startswith("http"):
                    if js_url.startswith("/"):
                        base = base_url.rstrip("/")
                        js_url = f"{base}{js_url}"
                    else:
                        js_url = f"{base_url.rstrip('/')}/{js_url}"
                
                try:
                    js_response = await self.client.get(js_url)
                    # Look for API endpoints, routes, etc.
                    patterns = [
                        r'["\'](/api/[^"\']+)["\']',
                        r'["\'](/v\d+/[^"\']+)["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                        r'urls?:\s*["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, js_response.text)
                        for match in matches:
                            endpoints.append({
                                "url": match,
                                "source": js_url,
                                "method": "discovered_from_js",
                            })
                
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return endpoints
    
    async def gather_osint(
        self,
        search_emails: bool = True,
        search_employees: bool = False,
        check_leaks: bool = True,
    ) -> dict:
        """Gather open-source intelligence."""
        osint_data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "emails": [],
            "leaks": [],
        }
        
        # Email discovery
        if search_emails:
            console.print("[blue]  ├─ Searching for email addresses...[/blue]")
            emails = await self._find_emails()
            osint_data["emails"] = emails
            console.print(f"[green]  └─ Found {len(emails)} email addresses[/green]")
        
        # Leak checking
        if check_leaks:
            console.print("[blue]  ├─ Checking for data leaks...[/blue]")
            # Placeholder - would integrate with services like HaveIBeenPwned
            console.print("[yellow]  └─ Leak checking requires API keys (coming soon)[/yellow]")
        
        # Save results
        output_file = self.output_dir / "osint.json"
        with open(output_file, "w") as f:
            json.dump(osint_data, f, indent=2)
        
        return osint_data
    
    async def _find_emails(self) -> list[str]:
        """Search for email addresses associated with target."""
        emails = set()
        
        try:
            # Search main page for emails
            url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            response = await self.client.get(url)
            
            # Email regex pattern
            email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(self.target)
            found = re.findall(email_pattern, response.text)
            emails.update(found)
            
            # Check common pages
            for path in ["/about", "/contact", "/team", "/careers"]:
                try:
                    resp = await self.client.get(f"{url.rstrip('/')}{path}")
                    found = re.findall(email_pattern, resp.text)
                    emails.update(found)
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return sorted(emails)
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
