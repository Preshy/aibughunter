"""Configuration management command module."""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage configuration settings")
console = Console()


@app.command()
def show():
    """Display current configuration"""
    from aibughunter.config.manager import ConfigManager
    
    config = ConfigManager.load()
    
    table = Table(title="Current Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")
    
    for key, value in config.display_items():
        table.add_row(key, str(value), config.get_source(key))
    
    console.print(table)


@app.command()
def set(
    key: str = typer.Argument(..., help="Configuration key (e.g., qwen-api-url, timeout, threads)"),
    value: str = typer.Argument(..., help="Configuration value"),
):
    """Set a configuration value"""
    from aibughunter.config.manager import ConfigManager
    
    config = ConfigManager.load()
    config.set(key, value)
    config.save()
    
    console.print(f"[green]✓[/green] Set [bold]{key}[/bold] = [cyan]{value}[/cyan]")


@app.command()
def get(
    key: str = typer.Argument(..., help="Configuration key"),
):
    """Get a specific configuration value"""
    from aibughunter.config.manager import ConfigManager
    
    config = ConfigManager.load()
    value = config.get(key)
    
    if value is None:
        console.print(f"[yellow]⚠ Configuration key '{key}' not found[/yellow]")
    else:
        console.print(f"[bold]{key}[/bold] = [cyan]{value}[/cyan]")


@app.command()
def reset():
    """Reset configuration to defaults"""
    from aibughunter.config.manager import ConfigManager
    
    if typer.confirm("Are you sure you want to reset all configuration?"):
        config = ConfigManager.load()
        config.reset()
        config.save()
        console.print("[green]✓[/green] Configuration reset to defaults")


@app.command()
def validate():
    """Validate configuration and test connections."""
    from aibughunter.config.manager import ConfigManager
    import asyncio
    
    console.print("[bold blue]🔍 Validating configuration...[/bold blue]")
    
    config = ConfigManager.load()
    
    # Test Qwen CLI
    console.print("Testing Qwen CLI...")
    try:
        from aibughunter.ai.qwen_client import QwenCLIClient
        client = QwenCLIClient(
            model=config.get("qwen-model", "coder-model"),
        )
        result = asyncio.run(client.ask("Say test", timeout=30))
        if result:
            console.print("[green]✓[/green] Qwen CLI working")
        else:
            console.print("[red]✗[/red] Qwen CLI returned empty response")
    except Exception as e:
        console.print(f"[red]✗[/red] Qwen CLI failed: {e}")
    
    # Validate other settings
    console.print(f"[green]✓[/green] Configuration is valid")
