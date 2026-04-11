"""CLI entry point for AI Bug Hunter."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aibughunter import __version__
from aibughunter.commands import scan, recon, report, config, tools, targets, kali, web

app = typer.Typer(
    name="aibughunter",
    help="🎯 AI-Powered Bug Hunting Platform",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()

# Add subcommands
app.add_typer(scan.app, name="scan", help="Run vulnerability scans on targets")
app.add_typer(recon.app, name="recon", help="Perform reconnaissance and OSINT")
app.add_typer(report.app, name="report", help="Generate bug bounty reports")
app.add_typer(config.app, name="config", help="Manage configuration settings")
app.add_typer(tools.app, name="tools", help="Manage security tools")
app.add_typer(targets.app, name="targets", help="Manage target scope and programs")
app.add_typer(kali.app, name="kali", help="🐉 Manage and run Kali Linux security tools")
app.add_typer(web.app, name="web", help="🌐 Web dashboard server")


def version_callback(value: bool):
    """Show version and exit."""
    if value:
        console.print(f"[bold green]AI Bug Hunter[/bold green] v{__version__}")
        console.print("AI-powered automated bug hunting platform with Qwen CLI integration")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
):
    """
    🎯 [bold]AI Bug Hunter[/bold] - Automated Bug Hunting Platform
    
    AI-powered security scanning tool that leverages Qwen CLI for intelligent
    vulnerability discovery, exploit development, and report generation.
    
    Examples:
    
    # Start a web application scan
    [bold]aibughunter scan web https://target.com --depth aggressive[/bold]
    
    # Perform reconnaissance
    [bold]aibughunter recon subdomains target.com[/bold]
    
    # Generate a bug bounty report
    [bold]aibughunter report generate --finding-id VULN-001[/bold]
    
    # Configure Qwen API
    [bold]aibughunter config set qwen-api-url http://localhost:8080[/bold]
    """
    pass


@app.command()
def hunt(
    target: str = typer.Argument(..., help="Target URL or domain to hunt"),
    scope: str = typer.Option("default", "--scope", "-s", help="Scope profile to use"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Scan depth: quick, standard, aggressive"),
    output_dir: str = typer.Option("./reports", "--output", "-o", help="Output directory for reports"),
    auto_exploit: bool = typer.Option(True, "--auto-exploit/--no-auto-exploit", help="Automatically attempt exploitation"),
    generate_report: bool = typer.Option(True, "--report/--no-report", help="Generate bug bounty report"),
):
    """
    🚀 Full automated hunt - End-to-end bug hunting workflow
    
    Performs reconnaissance, vulnerability scanning, exploitation attempts,
    and generates professional bug bounty reports automatically.
    """
    from aibughunter.core.orchestrator import BugHuntOrchestrator
    import asyncio
    
    console.print(Panel.fit(
        f"[bold green]Starting AI Bug Hunt[/bold green]\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"Scope: {scope} | Depth: {depth}\n"
        f"Auto-exploit: {'[green]Yes[/green]' if auto_exploit else '[yellow]No[/yellow]'}",
        title="🎯 AI Bug Hunter",
    ))
    
    orchestrator = BugHuntOrchestrator(
        scope=scope,
        depth=depth,
        output_dir=output_dir,
        auto_exploit=auto_exploit,
        generate_report=generate_report,
    )
    
    asyncio.run(orchestrator.run_hunt(target))


@app.command()
def dashboard():
    """📊 Show hunting dashboard and statistics"""
    from aibughunter.core.dashboard import DashboardRenderer
    
    dashboard = DashboardRenderer()
    dashboard.render()


if __name__ == "__main__":
    app()
