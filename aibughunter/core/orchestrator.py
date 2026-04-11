"""Bug hunt orchestrator - coordinates all scanning activities."""

import asyncio
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from aibughunter.config.manager import ConfigManager
from aibughunter.core.scope import ScopeManager
from aibughunter.core.database import Database
from aibughunter.scanners.recon_scanner import ReconScanner
from aibughunter.scanners.web_scanner import WebVulnerabilityScanner
from aibughunter.scanners.tech_scanner import run_tech_scanners
from aibughunter.tools.manager import ToolManager

console = Console()


class BugHuntOrchestrator:
    """Orchestrates automated bug hunting workflows."""

    def __init__(
        self,
        scope: str = "default",
        depth: str = "standard",
        output_dir: str = "./reports",
        auto_exploit: bool = True,
        generate_report: bool = True,
    ):
        self.scope_name = scope
        self.depth = depth
        self.output_dir = Path(output_dir)
        self.auto_exploit = auto_exploit
        self.generate_report = generate_report

        self.config = ConfigManager.load()
        self.scope_manager = ScopeManager()
        self.tool_manager = ToolManager()
        self.db = Database()

        self.findings = []
        self.scan_id = f"scan_{int(time.time())}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run_hunt(self, target: str):
        """Execute full bug hunting workflow."""
        start_time = time.time()

        # Register scan in database
        self.db.create_scan(self.scan_id, target, "full_hunt")

        try:
            # Phase 1: Setup & Validation
            await self._phase_setup(target)

            # Phase 2: Reconnaissance
            recon_data = await self._phase_recon(target)

            # Phase 3: Vulnerability Scanning
            findings = await self._phase_scan(target, recon_data)

            # Phase 4: Report Generation
            if self.generate_report:
                await self._phase_report(findings)

            # Summary
            elapsed = time.time() - start_time

            # Save findings to database
            if self.findings:
                self.db.save_findings_batch(self.findings, self.scan_id)
                self.db.complete_scan(self.scan_id, elapsed, len(self.findings))

            self._print_summary(elapsed)

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Hunt interrupted by user[/yellow]")
            await self._save_partial_results()
        except Exception as e:
            console.print(f"\n[red]❌ Hunt failed: {e}[/red]")
            await self._save_partial_results()
            raise

    async def _phase_setup(self, target: str):
        """Phase 1: Setup and validation."""
        console.print(Panel("[bold blue]Phase 1: Setup & Validation[/bold blue]", expand=False))

        # Validate target is in scope
        if not self.scope_manager.is_in_scope(target):
            console.print(f"[yellow]⚠ Target {target} not in scope. Adding temporarily.[/yellow]")
            self.scope_manager.add_target(target, scope_type="in", program=self.scope_name)

        # Ensure required tools are available
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Checking tools...", total=None)
            await self.tool_manager.ensure_tools(["nmap", "httpx"])
            progress.update(task, description="✓ Tools ready")

    async def _phase_recon(self, target: str) -> dict:
        """Phase 2: Reconnaissance."""
        console.print(Panel("[bold blue]Phase 2: Reconnaissance[/bold blue]", expand=False))

        recon = ReconScanner(target=target, output_dir=str(self.output_dir / "recon"))

        recon_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "endpoints": [],
            "technologies": {},
            "osint": {},
        }

        # Subdomain enumeration
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enumerating subdomains...", total=None)
            try:
                recon_data["subdomains"] = await recon.enumerate_subdomains(method="passive")
                progress.update(task, description=f"✓ Found {len(recon_data['subdomains'])} subdomains")
            except Exception as e:
                console.print(f"[yellow]⚠ Subdomain enumeration failed: {e}[/yellow]")
                progress.update(task, description="✗ Subdomain enumeration failed")

        # Tech stack analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing technologies...", total=None)
            try:
                recon_data["technologies"] = await recon.analyze_techstack(detailed=True)
                progress.update(task, description="✓ Tech stack analyzed")
            except Exception as e:
                console.print(f"[yellow]⚠ Tech analysis failed: {e}[/yellow]")
                progress.update(task, description="✗ Tech analysis failed")

        # Endpoint discovery
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Discovering endpoints...", total=None)
            try:
                recon_data["endpoints"] = await recon.discover_endpoints(crawl=True)
                progress.update(task, description=f"✓ Found {len(recon_data['endpoints'])} endpoints")
            except Exception as e:
                console.print(f"[yellow]⚠ Endpoint discovery failed: {e}[/yellow]")
                progress.update(task, description="✗ Endpoint discovery failed")

        # Summary
        console.print(Panel(
            f"[bold]Reconnaissance Complete[/bold]\n\n"
            f"Subdomains: {len(recon_data['subdomains'])}\n"
            f"Endpoints: {len(recon_data['endpoints'])}\n"
            f"Technologies: {len(recon_data['technologies'])}",
            title="📊 Recon Summary",
        ))

        return recon_data

    async def _phase_scan(self, target: str, recon_data: dict) -> list:
        """Phase 3: Vulnerability scanning."""
        console.print(Panel("[bold blue]Phase 3: Vulnerability Scanning[/bold blue]", expand=False))

        findings = []

        # Web application scanning (generic)
        try:
            web_scanner = WebVulnerabilityScanner(
                target=target,
                depth=self.depth,
                output_dir=str(self.output_dir),
            )
            web_findings = await web_scanner.run_scan()
            findings.extend(web_findings)
            console.print(f"[green]✓ Web scan complete: {len(web_findings)} findings[/green]")
            await web_scanner.close()
        except Exception as e:
            console.print(f"[yellow]⚠ Web scanning failed: {e}[/yellow]")

        # Tech-specific scanning (WordPress, Drupal, Laravel, etc.)
        try:
            tech_findings = await run_tech_scanners(
                target=target,
                technologies=recon_data.get("technologies", {}),
                output_dir=str(self.output_dir),
            )
            findings.extend(tech_findings)
            if tech_findings:
                console.print(f"[green]✓ Tech-specific scan complete: {len(tech_findings)} findings[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Tech-specific scanning failed: {e}[/yellow]")

        # Save tech scan results separately
        if tech_findings:
            tech_results_file = self.output_dir / f"tech_scan_{int(time.time())}.json"
            with open(tech_results_file, "w") as f:
                json.dump({
                    "target": target,
                    "detected_techs": tech_findings,
                    "timestamp": datetime.now().isoformat(),
                    "findings": tech_findings,
                }, f, indent=2)

        self.findings = findings
        return findings

    async def _phase_report(self, findings: list):
        """Phase 4: Report generation."""
        console.print(Panel("[bold blue]Phase 4: Report Generation[/bold blue]", expand=False))

        from aibughunter.reports.generator import ReportGenerator

        generator = ReportGenerator(
            output_dir=str(self.output_dir),
            template="hackerone",
            output_format="markdown",
        )

        await generator.generate_from_findings(findings, scan_id=self.scan_id)
        console.print(f"[green]✓ Report generated in {self.output_dir}[/green]")

    def _print_summary(self, elapsed: float):
        """Print hunt summary."""
        console.print(Panel(
            f"[bold green]🎯 Bug Hunt Complete[/bold green]\n\n"
            f"Findings: {len(self.findings)}\n"
            f"Time: {elapsed:.1f} seconds\n"
            f"Reports: {self.output_dir}",
            title="Summary",
        ))

    async def _save_partial_results(self):
        """Save partial results on interruption or failure."""
        if self.findings:
            import json
            results_file = self.output_dir / f"partial_{self.scan_id}.json"
            with open(results_file, "w") as f:
                json.dump({
                    "scan_id": self.scan_id,
                    "findings": self.findings,
                    "timestamp": datetime.now().isoformat(),
                }, f, indent=2)
            console.print(f"[yellow]📁 Partial results saved to {results_file}[/yellow]")
