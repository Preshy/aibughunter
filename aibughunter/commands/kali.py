"""Kali Linux tools command module."""

import typer
from typing import Optional, List
from rich.console import Console

app = typer.Typer(help="🐉 Manage and run Kali Linux security tools")
console = Console()


@app.command()
def list(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    installed: bool = typer.Option(False, "--installed", "-i", help="Show only installed tools"),
):
    """📋 List all available Kali Linux security tools
    
    Categories: reconnaissance, vulnerability_scanning, exploitation, 
    web_application, password_attacks, sniffing_spoofing, wireless, 
    forensics, post_exploitation, maintaining_access
    """
    from aibughunter.tools.kali_tools import KaliToolsManager, ToolCategory
    
    manager = KaliToolsManager()
    
    cat = None
    if category:
        try:
            cat = ToolCategory(category)
        except ValueError:
            console.print(f"[red]Invalid category: {category}[/red]")
            console.print("Available categories:")
            for c in ToolCategory:
                console.print(f"  - {c.value}")
            return
    
    manager.display_tools(category=cat, installed_only=installed)


@app.command()
def search(
    query: str = typer.Argument(..., help="Search term (e.g., 'sql', 'scan', 'web')"),
):
    """🔍 Search for Kali tools by keyword"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    from rich.table import Table
    
    manager = KaliToolsManager()
    results = manager.search_tools(query)
    
    if not results:
        console.print(f"[yellow]No tools found matching: {query}[/yellow]")
        return
    
    table = Table(title=f"Tools matching '{query}'")
    table.add_column("Tool", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Description", style="dim")
    
    for tool in results:
        status = "[green]✓[/green]" if tool.installed else "[red]✗[/red]"
        table.add_row(
            tool.name,
            tool.category.value,
            status,
            tool.description,
        )
    
    console.print(table)


@app.command()
def info(
    tool_name: str = typer.Argument(..., help="Tool name to get info for"),
):
    """ℹ️  Show detailed information about a specific tool"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    
    manager = KaliToolsManager()
    help_text = manager.get_tool_help(tool_name)
    console.print(help_text)


@app.command()
def install(
    tool_name: str = typer.Argument(None, help="Tool name to install (or 'all' for all tools)"),
):
    """📦 Install a Kali Linux tool"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    import asyncio
    
    manager = KaliToolsManager()
    
    if tool_name == "all" or tool_name is None:
        asyncio.run(manager.install_all())
    else:
        success = asyncio.run(manager.install_tool(tool_name))
        if success:
            console.print(f"[green]✓[/green] Use it with: [bold]aibughunter kali run {tool_name}[/bold]")


@app.command()
def run(
    tool_name: str = typer.Argument(..., help="Tool name to run"),
    args: List[str] = typer.Argument(None, help="Tool arguments"),
    output: str = typer.Option(None, "--output", "-o", help="Save output to file"),
    timeout: int = typer.Option(300, "--timeout", "-t", help="Timeout in seconds"),
):
    """🚀 Run a Kali Linux security tool"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    import asyncio
    
    manager = KaliToolsManager()
    
    result = asyncio.run(manager.run_tool(
        tool_name=tool_name,
        args=args or [],
        output_file=output,
        timeout=timeout,
    ))
    
    # Display results
    if result.get("output_file"):
        console.print(f"[green]✓[/green] Output saved to: {result['output_file']}")
    elif result.get("stdout"):
        console.print("\n[bold]Output:[/bold]")
        console.print(result["stdout"][:2000])  # Limit output
        if len(result.get("stdout", "")) > 2000:
            console.print(f"\n[dim]... (output truncated, use --output to save full results)[/dim]")
    
    if result.get("stderr"):
        console.print("\n[bold yellow]Errors:[/bold yellow]")
        console.print(result["stderr"][:1000])


@app.command()
def stats():
    """📊 Show tool usage statistics"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    from rich.table import Table
    
    manager = KaliToolsManager()
    
    total_tools = len(manager.KALI_TOOLS)
    installed = len([t for t in manager.KALI_TOOLS.values() if t.installed])
    
    # Category breakdown
    categories = {}
    for tool in manager.KALI_TOOLS.values():
        cat = tool.category.value
        if cat not in categories:
            categories[cat] = {"total": 0, "installed": 0}
        categories[cat]["total"] += 1
        if tool.installed:
            categories[cat]["installed"] += 1
    
    table = Table(title="🐉 Kali Linux Tools Statistics")
    table.add_column("Category", style="cyan")
    table.add_column("Total", style="green")
    table.add_column("Installed", style="yellow")
    table.add_column("Progress", style="blue")
    
    for cat, counts in categories.items():
        progress = counts["installed"] / counts["total"] * 100
        bar = "█" * int(progress / 10) + "░" * (10 - int(progress / 10))
        table.add_row(
            cat,
            str(counts["total"]),
            str(counts["installed"]),
            f"{bar} {progress:.0f}%",
        )
    
    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {installed}/{total_tools} tools installed")


@app.command()
def quick_scan(
    target: str = typer.Argument(..., help="Target to scan"),
    scan_type: str = typer.Option("quick", "--type", "-t", help="Scan type: quick, standard, full"),
):
    """⚡ Quick scan using multiple tools"""
    from aibughunter.tools.kali_tools import KaliToolsManager
    import asyncio
    
    manager = KaliToolsManager()
    
    async def run_scan():
        # Determine which tools to use based on scan type
        if scan_type == "quick":
            tools_to_run = ["nmap"]
            nmap_args = ["-sV", "-sC", "--top-ports", "100", target]
        elif scan_type == "standard":
            tools_to_run = ["nmap", "nikto"]
            nmap_args = ["-sV", "-sC", "-O", "-p-", target]
            nikto_args = ["-h", target]
        else:  # full
            tools_to_run = ["nmap", "nikto", "nuclei"]
            nmap_args = ["-sV", "-sC", "-O", "-A", "-p-", "-T4", target]
            nikto_args = ["-h", target, "-C", "all"]
            nuclei_args = ["-u", target, "-severity", "critical,high"]
        
        console.print(f"[bold blue]🎯 Quick Scan: {target} ({scan_type})[/bold blue]\n")
        
        # Run nmap
        if "nmap" in tools_to_run and manager.KALI_TOOLS["nmap"].installed:
            console.print("[blue][1/3] Running Nmap...[/blue]")
            result = await manager.run_tool("nmap", nmap_args)
            if result.get("stdout"):
                console.print(result["stdout"][:1000])
        
        # Run nikto
        if "nikto" in tools_to_run and manager.KALI_TOOLS["nikto"].installed:
            console.print("\n[blue][2/3] Running Nikto...[/blue]")
            result = await manager.run_tool("nikto", nikto_args)
            if result.get("stdout"):
                console.print(result["stdout"][:1000])
        
        # Run nuclei
        if "nuclei" in tools_to_run and manager.KALI_TOOLS["nuclei"].installed:
            console.print("\n[blue][3/3] Running Nuclei...[/blue]")
            result = await manager.run_tool("nuclei", nuclei_args)
            if result.get("stdout"):
                console.print(result["stdout"][:1000])
        
        console.print("\n[green]✓[/green] Quick scan complete!")
    
    asyncio.run(run_scan())
