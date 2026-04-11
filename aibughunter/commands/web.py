"""Web dashboard command module."""

import typer
import uvicorn
from rich.console import Console

app = typer.Typer(help="🌐 Web dashboard server")
console = Console()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Run as background daemon"),
):
    """🌐 Start the web dashboard server
    
    Launches a web-based dashboard for viewing and managing findings.
    Access at http://localhost:8000
    
    Examples:
    
    # Start dashboard
    [bold]aibughunter web serve[/bold]
    
    # Run on different port
    [bold]aibughunter web serve --port 9000[/bold]
    
    # Run as background daemon
    [bold]aibughunter web serve --daemon[/bold]
    
    # Bind to all interfaces
    [bold]aibughunter web serve --host 0.0.0.0[/bold]
    """
    import subprocess
    import sys
    import os
    import time
    
    console.print(f"[bold green]🌐 Starting AI Bug Hunter Dashboard[/bold green]")
    console.print(f"   Host: [cyan]{host}[/cyan]")
    console.print(f"   Port: [cyan]{port}[/cyan]")
    console.print(f"   URL: [bold]http://{host}:{port}[/bold]")
    console.print("")
    
    if daemon:
        # Start uvicorn as a subprocess
        cmd = [
            sys.executable, "-m", "uvicorn",
            "aibughunter.web.api:app",
            "--host", host,
            "--port", str(port),
            "--log-level", "warning",
        ]
        
        if reload:
            cmd.append("--reload")
        
        # Start process in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        
        # Wait for server to start
        time.sleep(2)
        
        # Check if process is still running
        if process.poll() is None:
            console.print(f"[green]✓[/green] Dashboard running in background (PID: {process.pid})")
            console.print(f"[green]✓[/green] Open: [bold]http://{host}:{port}[/bold]")
            console.print(f"[yellow]To stop: aibughunter web stop[/yellow]")
            
            # Save PID file
            pid_file = os.path.expanduser("~/.aibughunter/dashboard.pid")
            os.makedirs(os.path.dirname(pid_file), exist_ok=True)
            with open(pid_file, "w") as f:
                f.write(str(process.pid))
            
            console.print(f"[dim]PID saved to {pid_file}[/dim]")
        else:
            console.print(f"[red]✗[/red] Failed to start dashboard")
            console.print(f"[dim]Check logs: aibughunter web serve (without --daemon)[/dim]")
    else:
        # Run in foreground
        import uvicorn
        uvicorn.run(
            "aibughunter.web.api:app",
            host=host,
            port=port,
            reload=reload,
        )


@app.command()
def stop():
    """🛑 Stop the web dashboard daemon"""
    import os
    
    pid_file = os.path.expanduser("~/.aibughunter/dashboard.pid")
    
    if not os.path.exists(pid_file):
        console.print("[yellow]No dashboard daemon running[/yellow]")
        return
    
    with open(pid_file) as f:
        pid = int(f.read().strip())
    
    try:
        os.kill(pid, 9)
        os.remove(pid_file)
        console.print(f"[green]✓[/green] Dashboard daemon stopped (PID: {pid})")
    except ProcessLookupError:
        console.print("[yellow]Dashboard daemon not running[/yellow]")
        os.remove(pid_file)


@app.command()
def status():
    """📊 Check web dashboard daemon status"""
    import os
    
    pid_file = os.path.expanduser("~/.aibughunter/dashboard.pid")
    
    if not os.path.exists(pid_file):
        console.print("[yellow]Dashboard daemon is not running[/yellow]")
        console.print(f"[dim]Start with: aibughunter web serve --daemon[/dim]")
        return
    
    with open(pid_file) as f:
        pid = int(f.read().strip())
    
    try:
        os.kill(pid, 0)  # Check if process exists
        console.print(f"[green]✓[/green] Dashboard daemon running (PID: {pid})")
        console.print(f"[green]✓[/green] Access at: [bold]http://127.0.0.1:8000[/bold]")
    except ProcessLookupError:
        console.print("[red]✗[/red] Dashboard daemon not running (stale PID file)")
        os.remove(pid_file)
