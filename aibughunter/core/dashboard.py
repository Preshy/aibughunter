"""Dashboard renderer module."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from datetime import datetime

console = Console()


class DashboardRenderer:
    """Renders the hunting dashboard."""
    
    def __init__(self):
        self.console = Console()
    
    def render(self):
        """Render the complete dashboard."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        
        layout["left"].split_column(
            Layout(name="stats"),
            Layout(name="recent_findings"),
        )
        
        layout["right"].split_column(
            Layout(name="scope"),
            Layout(name="tools"),
        )
        
        layout["header"].update(self._render_header())
        layout["stats"].update(self._render_stats())
        layout["recent_findings"].update(self._render_recent_findings())
        layout["scope"].update(self._render_scope())
        layout["tools"].update(self._render_tools_status())
        
        self.console.print(layout)
    
    def _render_header(self) -> Panel:
        """Render dashboard header."""
        return Panel(
            "[bold green]🎯 AI Bug Hunter Dashboard[/bold green]\n"
            f"[dim]Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            style="bold",
        )
    
    def _render_stats(self) -> Panel:
        """Render statistics panel."""
        from aibughunter.core.database import Database
        
        db = Database()
        stats = db.get_stats()
        
        total = stats["total_findings"]
        critical = stats["by_severity"].get("critical", 0)
        high = stats["by_severity"].get("high", 0)
        medium = stats["by_severity"].get("medium", 0)
        low = stats["by_severity"].get("low", 0)
        
        stats_text = f"""
[bold]Total Findings:[/bold] {total}

[critical]Critical:[/critical] {critical}
[bold red]High:[/bold red]     {high}
[bold yellow]Medium:[/bold yellow] {medium}
[bold green]Low:[/bold green]    {low}
"""
        
        return Panel(stats_text, title="📊 Statistics", border_style="blue")
    
    def _render_recent_findings(self) -> Panel:
        """Render recent findings panel."""
        from aibughunter.core.database import Database
        
        db = Database()
        findings = db.get_findings(limit=5)
        
        if not findings:
            return Panel("No findings yet. Start a hunt!", title="🔍 Recent Findings", border_style="blue")
        
        table = Table(show_header=True, show_lines=True)
        table.add_column("ID", style="cyan", width=15)
        table.add_column("Title", style="green", width=30)
        table.add_column("Severity", style="yellow", width=10)
        
        for finding in findings:
            severity = finding.get("severity", "unknown").upper()
            table.add_row(
                finding.get("id", "N/A"),
                finding.get("title", "Unknown")[:30],
                severity,
            )
        
        return Panel(table, title="🔍 Recent Findings", border_style="blue")
    
    def _render_scope(self) -> Panel:
        """Render scope panel."""
        from aibughunter.core.database import Database
        
        db = Database()
        targets = db.list_targets()
        
        if not targets:
            return Panel("No targets configured.", title="🎯 Scope", border_style="blue")
        
        targets_text = ""
        for target in targets[:10]:  # Show first 10
            targets_text += f"• {target['target']}\n"
        
        if len(targets) > 10:
            targets_text += f"... and {len(targets) - 10} more"
        
        return Panel(targets_text, title="🎯 Scope", border_style="blue")
    
    def _render_tools_status(self) -> Panel:
        """Render tools status panel."""
        from aibughunter.tools.kali_tools import KaliToolsManager
        
        kali_manager = KaliToolsManager()
        tools = kali_manager.list_tools(installed_only=False)
        
        installed = len([t for t in tools if t.installed])
        total = len(tools)
        
        tools_text = f"[green]Installed:[/green] {installed}/{total}\n\n"
        
        # Show some key tools
        key_tools = ["nmap", "sqlmap", "nikto", "ffuf", "gobuster", "nuclei"]
        for tool_name in key_tools:
            tool = next((t for t in tools if t.name == tool_name), None)
            if tool:
                status = "[green]✓[/green]" if tool.installed else "[red]✗[/red]"
                tools_text += f"{status} {tool_name}\n"
        
        return Panel(tools_text, title="🛠️ Tools Status", border_style="blue")
