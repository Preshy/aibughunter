"""Report generation command module."""

import typer
from rich.console import Console

app = typer.Typer(help="Generate bug bounty reports")
console = Console()


@app.command()
def generate(
    finding_id: str = typer.Option(None, "--finding-id", "-f", help="Specific finding ID to report"),
    scan_id: str = typer.Option(None, "--scan-id", "-s", help="Generate report from entire scan"),
    format: str = typer.Option("both", "--format", "-fmt", help="Output format: markdown, html, json, both"),
    severity: str = typer.Option(None, "--severity", help="Filter by minimum severity (low, medium, high, critical)"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
    template: str = typer.Option("hackerone", "--template", "-t", help="Report template: hackerone, bugcrowd, custom"),
):
    """Generate professional bug bounty report
    
    Generates reports in Markdown, HTML, or both formats.
    HTML reports include interactive severity badges, summary cards,
    and professional styling suitable for client delivery.
    """
    from aibughunter.reports.generator import ReportGenerator
    import asyncio
    
    console.print(f"[bold blue]📝 Generating bug bounty report[/bold blue]")
    
    generator = ReportGenerator(
        output_dir=output,
        template=template,
        output_format=format if format != "both" else "markdown",
    )
    
    asyncio.run(generator.generate(
        finding_id=finding_id,
        scan_id=scan_id,
        min_severity=severity,
    ))


@app.command()
def list_findings(
    scan_id: str = typer.Option(None, "--scan-id", "-s", help="Filter by scan ID"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity"),
    status: str = typer.Option(None, "--status", help="Filter by status (new, triaged, reported)"),
):
    """List all discovered vulnerabilities"""
    from aibughunter.reports.finding_store import FindingStore
    from rich.table import Table
    
    store = FindingStore()
    findings = store.list_findings(scan_id=scan_id, severity=severity, status=status)
    
    if not findings:
        console.print("[yellow]No findings found[/yellow]")
        return
    
    table = Table(title="Discovered Vulnerabilities")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Target", style="blue")
    table.add_column("Status", style="magenta")
    table.add_column("Discovered", style="dim")
    
    for finding in findings:
        severity_color = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }.get(finding.severity.lower(), "white")
        
        table.add_row(
            finding.id,
            finding.title,
            f"[{severity_color}]{finding.severity.upper()}[/{severity_color}]",
            finding.target,
            finding.status,
            finding.discovered_at.strftime("%Y-%m-%d %H:%M"),
        )
    
    console.print(table)


@app.command()
def poc(
    finding_id: str = typer.Argument(..., help="Finding ID to generate POC for"),
    format: str = typer.Option("markdown", "--format", "-fmt", help="Output format"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
):
    """Generate Proof of Concept (POC) for a vulnerability"""
    from aibughunter.reports.poc_generator import POCGenerator
    import asyncio
    
    console.print(f"[bold blue]🔬 Generating POC for finding[/bold blue] [cyan]{finding_id}[/cyan]")
    
    generator = POCGenerator(output_dir=output)
    asyncio.run(generator.generate_poc(finding_id=finding_id, output_format=format))


@app.command()
def export(
    format: str = typer.Option("json", "--format", "-fmt", help="Export format: json, csv, xml"),
    output: str = typer.Option("./reports/export.json", "--output", "-o", help="Output file path"),
    scan_id: str = typer.Option(None, "--scan-id", "-s", help="Filter by scan ID"),
):
    """Export findings in various formats"""
    from aibughunter.reports.exporter import FindingsExporter
    import asyncio
    
    console.print(f"[bold blue]📤 Exporting findings to[/bold blue] [cyan]{output}[/cyan]")
    
    exporter = FindingsExporter(output_dir=output)
    asyncio.run(exporter.export(
        format=format,
        output_path=output,
        scan_id=scan_id,
    ))
