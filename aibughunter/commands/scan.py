"""Scan command module."""

import typer
from rich.console import Console

app = typer.Typer(help="Run vulnerability scans on targets")
console = Console()


@app.command()
def web(
    target: str = typer.Argument(..., help="Target URL to scan (e.g., https://example.com)"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Scan depth: quick, standard, aggressive"),
    auth: str = typer.Option(None, "--auth", "-a", help="Authentication token or cookie"),
    exclude: list[str] = typer.Option(None, "--exclude", "-e", help="URL paths to exclude"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
):
    """Scan web applications for vulnerabilities (XSS, SQLi, SSRF, etc.)"""
    from aibughunter.scanners.web_scanner import WebVulnerabilityScanner
    import asyncio
    
    console.print(f"[bold blue]🔍 Starting web scan on[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = WebVulnerabilityScanner(
        target=target,
        depth=depth,
        auth=auth,
        excluded_paths=exclude or [],
        output_dir=output,
    )
    
    asyncio.run(scanner.run_scan())


@app.command()
def api(
    target: str = typer.Argument(..., help="API endpoint or OpenAPI spec URL"),
    api_type: str = typer.Option("rest", "--type", "-t", help="API type: rest, graphql, grpc"),
    auth: str = typer.Option(None, "--auth", "-a", help="Authentication header"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
):
    """Scan APIs for security flaws (IDOR, auth bypass, injection, etc.)"""
    from aibughunter.scanners.api_scanner import APIScanner
    import asyncio
    
    console.print(f"[bold blue]🔍 Starting API scan on[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = APIScanner(
        target=target,
        api_type=api_type,
        auth=auth,
        output_dir=output,
    )
    
    asyncio.run(scanner.run_scan())


@app.command()
def infra(
    target: str = typer.Argument(..., help="Target IP or domain"),
    ports: str = typer.Option("top-1000", "--ports", "-p", help="Port range: top-100, top-1000, all, or custom like 80,443,8080"),
    services: bool = typer.Option(True, "--services/--no-services", help="Detect service versions"),
    vulns: bool = typer.Option(True, "--vulns/--no-vulns", help="Check for known vulnerabilities"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
):
    """Infrastructure scanning (ports, services, misconfigurations)"""
    from aibughunter.scanners.infra_scanner import InfrastructureScanner
    import asyncio
    
    console.print(f"[bold blue]🔍 Starting infrastructure scan on[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = InfrastructureScanner(
        target=target,
        port_range=ports,
        detect_services=services,
        check_vulns=vulns,
        output_dir=output,
    )
    
    asyncio.run(scanner.run_scan())


@app.command()
def mobile(
    target: str = typer.Argument(..., help="Path to APK/IPA file or app package name"),
    platform: str = typer.Option("auto", "--platform", "-p", help="Platform: android, ios, auto"),
    static_analysis: bool = typer.Option(True, "--static/--no-static", help="Perform static analysis"),
    dynamic_analysis: bool = typer.Option(False, "--dynamic/--no-dynamic", help="Perform dynamic analysis"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
):
    """Mobile application security testing (APK/IPA analysis)"""
    from aibughunter.scanners.mobile_scanner import MobileScanner
    import asyncio
    
    console.print(f"[bold blue]🔍 Starting mobile app scan on[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = MobileScanner(
        target=target,
        platform=platform,
        static_analysis=static_analysis,
        dynamic_analysis=dynamic_analysis,
        output_dir=output,
    )
    
    asyncio.run(scanner.run_scan())
