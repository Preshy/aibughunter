"""Tech-specific vulnerability scanners - selects tools based on detected technology stack."""

import asyncio
import json
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class TechScanner:
    """Base class for technology-specific scanners."""

    def __init__(self, target: str, output_dir: str = "./reports"):
        self.target = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    async def run(self) -> list[dict]:
        """Run the tech-specific scan. Override in subclasses."""
        return []

    def _add_finding(self, vuln_type: str, severity: str, title: str, description: str, **kwargs) -> dict:
        """Add a finding to results."""
        finding = {
            "id": f"{vuln_type.upper()[:4]}-{len(self.findings)+1:03d}",
            "type": vuln_type,
            "severity": severity,
            "title": title,
            "description": description,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        self.findings.append(finding)
        return finding


class WordPressScanner(TechScanner):
    """Scans WordPress sites using wpscan and custom checks."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ WordPress detected[/blue]")
        
        # Install wpscan if missing
        has_wpscan = await self._ensure_wpscan()
        
        if has_wpscan:
            await self._run_wpscan()
        
        # Always run manual checks
        await self._manual_wp_checks()
        
        console.print(f"[green]  └─ WordPress scan complete ({len(self.findings)} findings)[/green]")
        return self.findings

    async def _ensure_wpscan(self) -> bool:
        """Install wpscan if not present. Returns True if available."""
        if shutil.which("wpscan"):
            return True
        
        console.print("[blue]  │  ⚠ wpscan not found — installing...[/blue]")
        
        try:
            process = await asyncio.create_subprocess_shell(
                "gem install wpscan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120,
            )
            
            if process.returncode == 0:
                console.print("[green]  │  ✓ wpscan installed[/green]")
                return True
            else:
                err = stderr.decode("utf-8", errors="ignore").strip()
                console.print(f"[yellow]  │  ⚠ wpscan install failed: {err[:100]}[/yellow]")
                console.print("[yellow]  │  Falling back to manual WordPress checks[/yellow]")
                return False
        except asyncio.TimeoutError:
            console.print("[yellow]  │  ⚠ wpscan install timed out[/yellow]")
            return False
        except Exception as e:
            console.print(f"[yellow]  │  ⚠ wpscan install error: {e}[/yellow]")
            return False

    async def _run_wpscan(self):
        """Run wpscan against the target."""
        try:
            process = await asyncio.create_subprocess_exec(
                "wpscan",
                "--url", self.target,
                "--enumerate", "vp,vt,tt,cb,dbe",
                "--random-user-agent",
                "--no-banner",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300,
            )
            
            output = stdout.decode("utf-8", errors="ignore")
            self._parse_wpscan_output(output)
        except asyncio.TimeoutError:
            console.print("[yellow]  │  ⚠ wpscan timed out[/yellow]")
        except Exception as e:
            console.print(f"[yellow]  │  ⚠ wpscan error: {e}[/yellow]")

    def _parse_wpscan_output(self, output: str):
        """Parse wpscan output for findings."""
        # Look for identified vulnerabilities
        vuln_patterns = [
            (r"\[!\].*?(.*)", "high"),
            (r"\[?].*?(.*)", "medium"),
        ]
        
        for line in output.split("\n"):
            line = line.strip()
            if "[!]" in line:
                self._add_finding(
                    "wordpress_vuln", "high",
                    f"wpscan finding: {line[:80]}",
                    f"wpscan identified: {line}",
                    tool="wpscan",
                )
            elif "[?]" in line:
                self._add_finding(
                    "wordpress_info", "info",
                    f"wpscan info: {line[:80]}",
                    f"wpscan detected: {line}",
                    tool="wpscan",
                )

    async def _manual_wp_checks(self):
        """Manual WordPress security checks without wpscan."""
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for wp-config.php exposure
            resp = await client.get(f"{self.target}/wp-config.php")
            if resp.status_code == 200 and len(resp.text) > 0:
                self._add_finding(
                    "wordpress_config", "critical",
                    "wp-config.php publicly accessible",
                    "The WordPress configuration file is publicly accessible and may contain database credentials and salts.",
                    url=f"{self.target}/wp-config.php",
                )

            # Check for XML-RPC enabled
            resp = await client.get(f"{self.target}/xmlrpc.php")
            if resp.status_code == 200:
                self._add_finding(
                    "wordpress_xmlrpc", "medium",
                    "XML-RPC interface enabled",
                    "The xmlrpc.php endpoint is enabled, which can be used for brute-force amplification attacks.",
                    url=f"{self.target}/xmlrpc.php",
                )

            # Check for WP-JSON API exposure
            resp = await client.get(f"{self.target}/wp-json/")
            if resp.status_code == 200:
                self._add_finding(
                    "wordpress_api", "info",
                    "WordPress REST API exposed",
                    "The WordPress REST API is publicly accessible and may expose user data or site structure.",
                    url=f"{self.target}/wp-json/",
                )

            # Check for wp-login.php (admin exposure)
            resp = await client.get(f"{self.target}/wp-login.php")
            if resp.status_code == 200:
                self._add_finding(
                    "wordpress_login", "info",
                    "WordPress login page exposed",
                    "The WordPress admin login page is accessible at the default location.",
                    url=f"{self.target}/wp-login.php",
                )

            # Check for directory listing in uploads
            resp = await client.get(f"{self.target}/wp-content/uploads/")
            if resp.status_code == 200 and ("Index of" in resp.text or "Directory listing" in resp.text):
                self._add_finding(
                    "wordpress_upload_listing", "high",
                    "WordPress uploads directory listing enabled",
                    "The uploads directory allows directory listing, potentially exposing sensitive uploaded files.",
                    url=f"{self.target}/wp-content/uploads/",
                )


class DrupalScanner(TechScanner):
    """Scans Drupal sites."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ Drupal detected — running Drupal checks...[/blue]")
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for CHANGELOG.txt (version disclosure)
            resp = await client.get(f"{self.target}/CHANGELOG.txt")
            if resp.status_code == 200:
                version_match = re.search(r"Drupal\s+([\d.]+)", resp.text)
                version = version_match.group(1) if version_match else "unknown"
                self._add_finding(
                    "drupal_version_disclosure", "medium",
                    "Drupal version disclosed via CHANGELOG.txt",
                    f"CHANGELOG.txt is publicly accessible, revealing Drupal version {version}.",
                    url=f"{self.target}/CHANGELOG.txt",
                )

            # Check for update.php
            resp = await client.get(f"{self.target}/update.php")
            if resp.status_code == 200:
                self._add_finding(
                    "drupal_update_exposed", "high",
                    "Drupal update.php exposed",
                    "The database update script is publicly accessible and could be exploited.",
                    url=f"{self.target}/update.php",
                )

            # Check REST API exposure
            resp = await client.get(f"{self.target}/jsonapi/")
            if resp.status_code == 200:
                self._add_finding(
                    "drupal_jsonapi", "info",
                    "Drupal JSON:API exposed",
                    "The JSON:API module is enabled and may expose data structures.",
                    url=f"{self.target}/jsonapi/",
                )

            # Check for admin path
            resp = await client.get(f"{self.target}/user/login")
            if resp.status_code == 200:
                self._add_finding(
                    "drupal_login", "info",
                    "Drupal login page exposed",
                    "The default Drupal login page is accessible.",
                    url=f"{self.target}/user/login",
                )
        
        console.print(f"[green]  └─ Drupal scan complete ({len(self.findings)} findings)[/green]")
        return self.findings


class JoomlaScanner(TechScanner):
    """Scans Joomla sites."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ Joomla detected — running Joomla checks...[/blue]")
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for configuration.php exposure
            resp = await client.get(f"{self.target}/configuration.php")
            if resp.status_code == 200 and len(resp.text) > 0:
                self._add_finding(
                    "joomla_config", "critical",
                    "configuration.php publicly accessible",
                    "The Joomla configuration file is publicly accessible.",
                    url=f"{self.target}/configuration.php",
                )

            # Check for administrator path
            resp = await client.get(f"{self.target}/administrator/")
            if resp.status_code == 200:
                self._add_finding(
                    "joomla_admin", "high",
                    "Joomla administrator panel exposed",
                    "The Joomla admin panel is accessible at the default location.",
                    url=f"{self.target}/administrator/",
                )

            # Check for version disclosure
            resp = await client.get(f"{self.target}/administrator/manifests/files/joomla.xml")
            if resp.status_code == 200:
                version_match = re.search(r"<version>([^<]+)</version>", resp.text)
                version = version_match.group(1) if version_match else "unknown"
                self._add_finding(
                    "joomla_version_disclosure", "medium",
                    f"Joomla version disclosed: {version}",
                    "The Joomla version can be determined from the manifest file.",
                    url=f"{self.target}/administrator/manifests/files/joomla.xml",
                )

            # Check for installation folder
            resp = await client.get(f"{self.target}/installation/")
            if resp.status_code == 200:
                self._add_finding(
                    "joomla_installation", "critical",
                    "Joomla installation folder not removed",
                    "The installation directory is still present and could be exploited.",
                    url=f"{self.target}/installation/",
                )
        
        console.print(f"[green]  └─ Joomla scan complete ({len(self.findings)} findings)[/green]")
        return self.findings


class LaravelScanner(TechScanner):
    """Scans Laravel applications."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ Laravel detected — running Laravel checks...[/blue]")
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for .env file (critical)
            resp = await client.get(f"{self.target}/.env")
            if resp.status_code == 200:
                self._add_finding(
                    "laravel_env_exposed", "critical",
                    "Laravel .env file publicly accessible",
                    "The .env file contains database credentials, APP_KEY, and other sensitive configuration.",
                    url=f"{self.target}/.env",
                )

            # Check for debug mode
            resp = await client.get(f"{self.target}/_debugbar/open")
            if resp.status_code == 200:
                self._add_finding(
                    "laravel_debugbar", "high",
                    "Laravel Debugbar endpoint accessible",
                    "The Debugbar is enabled and accessible, potentially exposing application internals.",
                    url=f"{self.target}/_debugbar/open",
                )

            # Check for Telescope exposure
            resp = await client.get(f"{self.target}/telescope")
            if resp.status_code == 200:
                self._add_finding(
                    "laravel_telescope", "high",
                    "Laravel Telescope exposed",
                    "Laravel Telescope is publicly accessible and exposes application debug data.",
                    url=f"{self.target}/telescope",
                )

            # Check for default error pages revealing stack traces
            resp = await client.get(f"{self.target}/nonexistent-page-test-404")
            if resp.status_code == 500 and ("stack trace" in resp.text.lower() or "traceback" in resp.text.lower()):
                self._add_finding(
                    "laravel_stack_trace", "high",
                    "Stack trace exposed on error",
                    "Application error pages reveal stack traces, indicating debug mode is enabled.",
                )
        
        console.print(f"[green]  └─ Laravel scan complete ({len(self.findings)} findings)[/green]")
        return self.findings


class DjangoScanner(TechScanner):
    """Scans Django applications."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ Django detected — running Django checks...[/blue]")
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for admin panel
            resp = await client.get(f"{self.target}/admin/")
            if resp.status_code == 200:
                self._add_finding(
                    "django_admin", "high",
                    "Django admin panel exposed",
                    "The Django admin panel is accessible at the default location.",
                    url=f"{self.target}/admin/",
                )

            # Check for debug toolbar
            resp = await client.get(f"{self.target}/__debug__/")
            if resp.status_code == 200:
                self._add_finding(
                    "django_debug_toolbar", "high",
                    "Django Debug Toolbar enabled",
                    "Debug Toolbar is enabled, exposing application internals.",
                    url=f"{self.target}/__debug__/",
                )

            # Check for default 500 error revealing debug
            resp = await client.get(f"{self.target}/nonexistent-test-500")
            if "Traceback" in resp.text or "Technical 500" in resp.text:
                self._add_finding(
                    "django_debug_mode", "high",
                    "Django DEBUG mode enabled",
                    "Error pages reveal Django is running in DEBUG mode, exposing internal details.",
                )
        
        console.print(f"[green]  └─ Django scan complete ({len(self.findings)} findings)[/green]")
        return self.findings


class NodeJSScanner(TechScanner):
    """Scans Node.js/Express applications."""

    async def run(self) -> list[dict]:
        console.print("[blue]  ├─ Node.js detected — running Node.js checks...[/blue]")
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Check for stack trace in error responses
            resp = await client.get(f"{self.target}/nonexistent-test-node")
            if "SyntaxError" in resp.text or "ReferenceError" in resp.text or "TypeError" in resp.text:
                self._add_finding(
                    "node_stack_trace", "high",
                    "Node.js stack trace exposed",
                    "Application error responses include Node.js stack traces.",
                )

            # Check for package.json exposure
            resp = await client.get(f"{self.target}/package.json")
            if resp.status_code == 200 and "dependencies" in resp.text:
                self._add_finding(
                    "node_package_json", "medium",
                    "package.json publicly accessible",
                    "Exposes dependency versions which can be used to find known vulnerabilities.",
                    url=f"{self.target}/package.json",
                )

            # Check for .npmrc exposure
            resp = await client.get(f"{self.target}/.npmrc")
            if resp.status_code == 200:
                self._add_finding(
                    "node_npmrc", "critical",
                    ".npmrc file publicly accessible",
                    "The .npmrc file may contain authentication tokens and registry credentials.",
                    url=f"{self.target}/.npmrc",
                )
        
        console.print(f"[green]  └─ Node.js scan complete ({len(self.findings)} findings)[/green]")
        return self.findings


# Registry of tech scanners
TECH_SCANNERS = {
    "wordpress": WordPressScanner,
    "drupal": DrupalScanner,
    "joomla": JoomlaScanner,
    "laravel": LaravelScanner,
    "django": DjangoScanner,
    "node": NodeJSScanner,
}


def detect_techs(technologies: dict) -> list[str]:
    """Detect which tech scanners to use based on recon data."""
    detected = []
    
    techs = technologies.get("technologies", {})
    headers = techs.get("headers", {})
    content = techs.get("content", {})
    cookies = techs.get("cookies", {})
    detailed = techs.get("detailed", {})
    
    # Combine all tech indicators into one string for matching
    all_tech = json.dumps(techs).lower()
    
    # CMS detection
    if "wordpress" in all_tech or "wp-content" in all_tech or "wp-" in json.dumps(cookies):
        detected.append("wordpress")
    elif "drupal" in all_tech:
        detected.append("drupal")
    elif "joomla" in all_tech:
        detected.append("joomla")
    
    # Framework detection
    if "laravel" in all_tech:
        detected.append("laravel")
    elif "django" in all_tech:
        detected.append("django")
    elif "node" in all_tech or "express" in all_tech:
        detected.append("node")
    
    return detected


async def run_tech_scanners(
    target: str,
    technologies: dict,
    output_dir: str = "./reports",
) -> list[dict]:
    """Run tech-specific scanners based on detected technology stack.
    
    Args:
        target: Target URL
        technologies: Tech stack data from recon
        output_dir: Output directory for reports
    
    Returns:
        List of findings from tech-specific scanners
    """
    detected_techs = detect_techs(technologies)
    
    if not detected_techs:
        console.print("[dim]  No specific tech scanners matched — skipping tech-specific scans[/dim]")
        return []
    
    console.print(Panel(
        f"[bold]Tech-Specific Scanners[/bold]\n"
        f"Detected: {', '.join(detected_techs)}\n"
        f"Running targeted scans for each technology...",
        title="🔧 Tech Scanners",
    ))
    
    all_findings = []
    
    for tech in detected_techs:
        scanner_class = TECH_SCANNERS.get(tech)
        if scanner_class:
            scanner = scanner_class(target=target, output_dir=output_dir)
            findings = await scanner.run()
            all_findings.extend(findings)
    
    return all_findings
