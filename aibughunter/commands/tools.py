"""Tools management command module."""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage security tools")
console = Console()


@app.command()
def list_tools():
    """List all available security tools"""
    from aibughunter.tools.manager import ToolManager
    from rich.table import Table
    
    manager = ToolManager()
    tools = manager.list_tools()
    
    table = Table(title="Available Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Description", style="dim")
    
    for tool in tools:
        status = "[green]Installed[/green]" if tool.installed else "[red]Not Installed[/red]"
        table.add_row(
            tool.name,
            tool.category,
            status,
            tool.description,
        )
    
    console.print(table)


@app.command()
def install(
    tool_name: str = typer.Argument(..., help="Tool name to install"),
    force: bool = typer.Option(False, "--force", "-f", help="Force reinstall"),
):
    """Install a security tool"""
    from aibughunter.tools.manager import ToolManager
    import asyncio
    
    manager = ToolManager()
    
    console.print(f"[bold blue]📦 Installing[/bold blue] [cyan]{tool_name}[/cyan]...")
    asyncio.run(manager.install_tool(tool_name, force=force))


@app.command()
def create(
    tool_type: str = typer.Argument(..., help="Type of tool to create: script, exploit, scanner"),
    description: str = typer.Option(..., "--description", "-d", help="Description of what the tool should do"),
    language: str = typer.Option("python", "--language", "-l", help="Programming language: python, bash, go"),
    output: str = typer.Option("./tools/custom", "--output", "-o", help="Output directory"),
):
    """AI-generate a custom security tool"""
    from aibughunter.tools.creator import ToolCreator
    import asyncio
    
    console.print(f"[bold blue]🤖 AI-generating[/bold blue] [cyan]{tool_type}[/cyan] tool...")
    
    creator = ToolCreator(output_dir=output)
    asyncio.run(creator.create_tool(
        tool_type=tool_type,
        description=description,
        language=language,
    ))


@app.command()
def update(
    tool_name: str = typer.Argument(None, help="Tool name to update (or all if not specified)"),
):
    """Update security tools to latest versions"""
    from aibughunter.tools.manager import ToolManager
    import asyncio
    
    manager = ToolManager()
    
    if tool_name:
        console.print(f"[bold blue]🔄 Updating[/bold blue] [cyan]{tool_name}[/cyan]...")
        asyncio.run(manager.update_tool(tool_name))
    else:
        console.print("[bold blue]🔄 Updating all tools[/bold blue]")
        asyncio.run(manager.update_all_tools())
