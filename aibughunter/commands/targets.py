"""Target scope management command module."""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage target scope and programs")
console = Console()


@app.command()
def add(
    target: str = typer.Argument(..., help="Target domain, URL, or IP range"),
    scope_type: str = typer.Option("in", "--type", "-t", help="Scope type: in (in-scope), out (out-of-scope)"),
    program: str = typer.Option("default", "--program", "-p", help="Bug bounty program name"),
    notes: str = typer.Option(None, "--notes", "-n", help="Additional notes about the target"),
):
    """Add a target to the scope"""
    from aibughunter.core.scope import ScopeManager
    
    manager = ScopeManager()
    manager.add_target(
        target=target,
        scope_type=scope_type,
        program=program,
        notes=notes,
    )
    
    console.print(f"[green]✓[/green] Added [cyan]{target}[/cyan] to {scope_type}-scope")


@app.command()
def remove(
    target: str = typer.Argument(..., help="Target to remove"),
):
    """Remove a target from scope"""
    from aibughunter.core.scope import ScopeManager
    
    manager = ScopeManager()
    manager.remove_target(target)
    
    console.print(f"[green]✓[/green] Removed [cyan]{target}[/cyan] from scope")


@app.command()
def list(
    program: str = typer.Option(None, "--program", "-p", help="Filter by program"),
    scope_type: str = typer.Option(None, "--type", "-t", help="Filter by scope type: in, out"),
):
    """List all targets in scope"""
    from aibughunter.core.scope import ScopeManager
    from rich.table import Table
    
    manager = ScopeManager()
    targets = manager.list_targets(program=program, scope_type=scope_type)
    
    if not targets:
        console.print("[yellow]No targets found[/yellow]")
        return
    
    table = Table(title="Target Scope")
    table.add_column("Target", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Program", style="blue")
    table.add_column("Added", style="dim")
    table.add_column("Notes", style="dim")
    
    for target in targets:
        type_style = "[green]IN[/green]" if target.scope_type == "in" else "[red]OUT[/red]"
        table.add_row(
            target.target,
            type_style,
            target.program,
            target.added_at.strftime("%Y-%m-%d"),
            target.notes or "",
        )
    
    console.print(table)


@app.command()
def import_scope(
    file_path: str = typer.Argument(..., help="Scope file path (JSON or text)"),
    program: str = typer.Option("default", "--program", "-p", help="Bug bounty program name"),
):
    """Import scope from file"""
    from aibughunter.core.scope import ScopeManager
    
    manager = ScopeManager()
    count = manager.import_scope(file_path, program=program)
    
    console.print(f"[green]✓[/green] Imported [cyan]{count}[/cyan] targets from {file_path}")


@app.command()
def export_scope(
    output: str = typer.Option("./scope.json", "--output", "-o", help="Output file path"),
    format: str = typer.Option("json", "--format", "-fmt", help="Export format: json, text"),
):
    """Export scope to file"""
    from aibughunter.core.scope import ScopeManager
    
    manager = ScopeManager()
    manager.export_scope(output, format=format)
    
    console.print(f"[green]✓[/green] Exported scope to [cyan]{output}[/cyan]")


@app.command()
def programs():
    """List bug bounty programs"""
    from aibughunter.core.scope import ScopeManager
    from rich.table import Table
    
    manager = ScopeManager()
    programs = manager.list_programs()
    
    if not programs:
        console.print("[yellow]No programs configured[/yellow]")
        return
    
    table = Table(title="Bug Bounty Programs")
    table.add_column("Program", style="cyan")
    table.add_column("Targets", style="green")
    table.add_column("Platform", style="blue")
    table.add_column("Status", style="yellow")
    
    for program in programs:
        table.add_row(
            program.name,
            str(program.target_count),
            program.platform or "N/A",
            "[green]Active[/green]" if program.active else "[red]Inactive[/red]",
        )
    
    console.print(table)
