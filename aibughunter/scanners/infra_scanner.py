"""Infrastructure scanner module."""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

import subprocess
from rich.console import Console

console = Console()


class InfrastructureScanner:
    """Scans infrastructure for security vulnerabilities."""
    
    def __init__(
        self,
        target: str,
        port_range: str = "top-1000",
        detect_services: bool = True,
        check_vulns: bool = True,
        output_dir: str = "./reports",
    ):
        self.target = target
        self.port_range = port_range
        self.detect_services = detect_services
        self.check_vulns = check_vulns
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings = []
    
    async def run_scan(self) -> list[dict]:
        """Run infrastructure scan."""
        console.print(f"[bold blue]Infrastructure Scan: {self.target}[/bold blue]")
        
        # Port scanning
        ports = await self._scan_ports()
        
        # Service detection
        if self.detect_services and ports:
            services = await self._detect_services(ports)
        
        # Vulnerability checking
        if self.check_vulns:
            await self._check_vulnerabilities()
        
        self._save_results()
        return self.findings
    
    async def _scan_ports(self) -> list[int]:
        """Scan for open ports."""
        console.print("[cyan]Scanning ports...[/cyan]")
        
        try:
            # Use nmap if available
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0:
                return await self._nmap_scan()
            else:
                console.print("[yellow]nmap not available, using basic port scan[/yellow]")
                return await self._basic_port_scan()
        
        except FileNotFoundError:
            console.print("[yellow]nmap not available, using basic port scan[/yellow]")
            return await self._basic_port_scan()
    
    async def _nmap_scan(self) -> list[int]:
        """Run nmap port scan."""
        port_arg = {
            "top-100": "--top-ports 100",
            "top-1000": "--top-ports 1000",
            "all": "-p-",
        }.get(self.port_range, self.port_range)
        
        cmd = f"nmap {port_arg} -oX - {self.target}"
        
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await process.communicate()
        
        # Parse nmap output (simplified)
        open_ports = []
        # In production, would properly parse XML output
        
        return open_ports
    
    async def _basic_port_scan(self) -> list[int]:
        """Basic port scan using Python."""
        import asyncio
        
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        
        open_ports = []
        
        # Scan common ports
        for port, service in common_ports.items():
            try:
                reader, writer = await asyncio.open_connection(
                    self.target,
                    port,
                )
                writer.close()
                await writer.wait_closed()
                
                open_ports.append(port)
                console.print(f"  [green]✓[/green] Port {port}/tcp open - {service}")
            
            except (ConnectionRefusedError, OSError):
                pass
            
            await asyncio.sleep(0.01)  # Rate limiting
        
        return open_ports
    
    async def _detect_services(self, ports: list[int]):
        """Detect services running on open ports."""
        console.print("[cyan]Detecting services...[/cyan]")
        # Would use nmap -sV in production
        pass
    
    async def _check_vulnerabilities(self):
        """Check for known vulnerabilities."""
        console.print("[cyan]Checking for vulnerabilities...[/cyan]")
        # Would integrate with CVE databases in production
        pass
    
    def _save_results(self):
        """Save scan results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"infra_scan_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "findings": self.findings,
            }, f, indent=2)
