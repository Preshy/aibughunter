"""Reconnaissance command module."""

import typer
from rich.console import Console

app = typer.Typer(help="Perform reconnaissance and OSINT")
console = Console()


@app.command()
def dork(
    categories: list[str] = typer.Argument(
        None,
        help="Dork categories: exposed_panels, config_files, sensitive_files, vulnerable_apps, cloud_storage, api_endpoints, error_pages, subdomains, custom",
    ),
    target: str = typer.Option(None, "--target", "-t", help="Specific target domain (replaces TARGET placeholder in dorks)"),
    max_results: int = typer.Option(100, "--max-results", "-m", help="Maximum number of results to return"),
    delay: float = typer.Option(2.0, "--delay", "-d", help="Delay between searches (seconds)"),
    output: str = typer.Option("./recon/dorks", "--output", "-o", help="Output directory"),
    display: bool = typer.Option(True, "--display/--no-display", help="Display results in table"),
    find_targets: bool = typer.Option(False, "--find-targets", help="Auto-find bug bounty targets"),
    add_custom: str = typer.Option(None, "--add-custom", help="Add a custom dork query"),
    list_categories: bool = typer.Option(False, "--list", help="List all available dork categories"),
):
    """🔍 Google Dork finder for automated target discovery

    Find exposed panels, config files, vulnerable applications, and more.

    Examples:

    # Find exposed admin panels
    [bold]aibughunter recon dork exposed_panels[/bold]

    # Find config files with credentials
    [bold]aibughunter recon dork config_files -m 50[/bold]

    # Find targets for a specific domain
    [bold]aibughunter recon dork subdomains -t example.com[/bold]

    # Find bug bounty targets automatically
    [bold]aibughunter recon dork --find-targets[/bold]

    # Add a custom dork
    [bold]aibughunter recon dork --add-custom "inurl:login site:example.com"[/bold]

    # List all available categories
    [bold]aibughunter recon dork --list[/bold]
    """
    from aibughunter.scanners.dork_finder import GoogleDorkFinder
    import asyncio

    # Handle list categories
    if list_categories:
        finder = GoogleDorkFinder(output_dir=output)
        cats = finder.list_dork_categories()

        from rich.table import Table
        table = Table(title="Available Dork Categories")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Sample Dorks", style="dim")

        for cat_name, cat_info in cats.items():
            sample = ", ".join(cat_info["dorks"][:3])
            if len(cat_info["dorks"]) > 3:
                sample += "..."
            table.add_row(
                cat_name,
                str(cat_info["count"]),
                sample,
            )

        console.print(table)
        return

    # Handle add custom dork
    if add_custom:
        finder = GoogleDorkFinder(output_dir=output)
        finder.add_custom_dork(
            query=add_custom,
            category="custom",
            description="User-defined custom dork",
            severity="medium",
        )
        return

    def run_dork_search():
        finder = GoogleDorkFinder(output_dir=output)
        
        async def _search():
            if find_targets:
                results = await finder.find_targets_for_bounty(
                    program_type="all",
                    max_results=max_results,
                )
            else:
                results = await finder.search(
                    categories=categories,
                    target=target,
                    max_results=max_results,
                )
            
            if display and results:
                finder.display_results()
        
        import asyncio
        asyncio.run(_search())
    
    run_dork_search()


@app.command()
def subdomains(
    domain: str = typer.Argument(..., help="Target domain for subdomain enumeration"),
    method: str = typer.Option("all", "--method", "-m", help="Method: brute-force, passive, all"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Custom wordlist path"),
    output: str = typer.Option("./recon", "--output", "-o", help="Output directory"),
):
    """Enumerate subdomains using multiple techniques"""
    from aibughunter.scanners.recon_scanner import ReconScanner
    import asyncio
    
    console.print(f"[bold blue]🔎 Enumerating subdomains for[/bold blue] [cyan]{domain}[/cyan]")
    
    scanner = ReconScanner(
        target=domain,
        output_dir=output,
    )
    
    asyncio.run(scanner.enumerate_subdomains(method=method, wordlist=wordlist))


@app.command()
def techstack(
    target: str = typer.Argument(..., help="Target URL or domain"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Deep technology fingerprinting"),
    output: str = typer.Option("./recon", "--output", "-o", help="Output directory"),
):
    """Identify technologies, frameworks, and services in use"""
    from aibughunter.scanners.recon_scanner import ReconScanner
    import asyncio
    
    console.print(f"[bold blue]🔎 Analyzing tech stack for[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = ReconScanner(
        target=target,
        output_dir=output,
    )
    
    asyncio.run(scanner.analyze_techstack(detailed=detailed))


@app.command()
def endpoints(
    target: str = typer.Argument(..., help="Target URL or domain"),
    crawl: bool = typer.Option(True, "--crawl/--no-crawl", help="Actively crawl the site"),
    js_analysis: bool = typer.Option(True, "--js/--no-js", help="Analyze JavaScript files for endpoints"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Wordlist for endpoint brute-forcing"),
    output: str = typer.Option("./recon", "--output", "-o", help="Output directory"),
):
    """Discover hidden endpoints, API routes, and attack surface"""
    from aibughunter.scanners.recon_scanner import ReconScanner
    import asyncio
    
    console.print(f"[bold blue]🔎 Discovering endpoints for[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = ReconScanner(
        target=target,
        output_dir=output,
    )
    
    asyncio.run(scanner.discover_endpoints(
        crawl=crawl,
        js_analysis=js_analysis,
    ))


@app.command()
def osint(
    target: str = typer.Argument(..., help="Target domain or organization"),
    emails: bool = typer.Option(True, "--emails/--no-emails", help="Search for email addresses"),
    employees: bool = typer.Option(False, "--employees/--no-employees", help="Find employee information"),
    leaks: bool = typer.Option(True, "--leaks/--no-leaks", help="Check for data leaks"),
    output: str = typer.Option("./recon", "--output", "-o", help="Output directory"),
):
    """Open-source intelligence gathering"""
    from aibughunter.scanners.recon_scanner import ReconScanner
    import asyncio
    
    console.print(f"[bold blue]🔎 Performing OSINT on[/bold blue] [cyan]{target}[/cyan]")
    
    scanner = ReconScanner(
        target=target,
        output_dir=output,
    )
    
    asyncio.run(scanner.gather_osint(
        search_emails=emails,
        search_employees=employees,
        check_leaks=leaks,
    ))
