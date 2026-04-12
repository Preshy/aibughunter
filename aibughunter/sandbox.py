"""Docker sandbox for running security tools in isolated containers."""

import asyncio
import json
import shutil
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()


# Registry of security tools and their Docker images
SECURITY_TOOLS = {
    "wpscan": {
        "image": "wpscanteam/wpscan",
        "description": "WordPress vulnerability scanner",
        "dockerhub": "https://hub.docker.com/r/wpscanteam/wpscan",
    },
    "nikto": {
        "image": "kalilinux/nikto",
        "description": "Web server vulnerability scanner",
        "dockerhub": "https://hub.docker.com/r/kalilinux/nikto",
    },
    "nuclei": {
        "image": "projectdiscovery/nuclei",
        "description": "Fast vulnerability scanner",
        "dockerhub": "https://hub.docker.com/r/projectdiscovery/nuclei",
    },
    "nmap": {
        "image": "instrumentisto/nmap",
        "description": "Network discovery and security auditing",
        "dockerhub": "https://hub.docker.com/r/instrumentisto/nmap",
    },
    "sqlmap": {
        "image": "paaul/sqlmap",
        "description": "Automatic SQL injection detection",
        "dockerhub": "https://hub.docker.com/r/paaul/sqlmap",
    },
}


async def docker_available() -> bool:
    """Check if Docker is available on the system."""
    return shutil.which("docker") is not None


async def pull_image(image: str) -> bool:
    """Pull a Docker image if not already present. Returns True on success."""
    try:
        # Check if image exists locally
        check = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await check.communicate()

        if check.returncode == 0:
            return True  # Already present

        # Pull the image
        console.print(f"[blue]  │  Pulling {image}...[/blue]")
        process = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=300,  # 5 min for large images
        )

        if process.returncode == 0:
            return True
        else:
            err = stderr.decode("utf-8", errors="ignore").strip().split("\n")[-1]
            console.print(f"[yellow]  │  ⚠ Pull failed: {err}[/yellow]")
            return False

    except asyncio.TimeoutError:
        console.print("[yellow]  │  ⚠ Pull timed out[/yellow]")
        return False
    except Exception as e:
        console.print(f"[yellow]  │  ⚠ Docker error: {e}[/yellow]")
        return False


async def run_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 180,
    network_access: bool = True,
) -> tuple[str, str, int]:
    """Run a security tool in a Docker container.
    
    Args:
        tool_name: Tool key from SECURITY_TOOLS
        args: Arguments to pass to the tool inside the container
        timeout: Max seconds before killing the container
        network_access: Allow network access (--network host)
    
    Returns:
        (stdout, stderr, return_code)
    """
    tool = SECURITY_TOOLS.get(tool_name)
    if not tool:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(SECURITY_TOOLS.keys())}")

    # Ensure image is available
    if not await pull_image(tool["image"]):
        return ("", f"Failed to pull image {tool['image']}", 1)

    # Build docker command
    cmd = [
        "docker", "run", "--rm",
    ]

    if network_access:
        cmd.extend(["--network", "host"])

    # Add container name as a label for cleanup tracking
    container_name = f"aibh-{tool_name}-{uuid.uuid4().hex[:8]}"
    cmd.extend(["--name", container_name])

    cmd.append(tool["image"])
    cmd.extend(args)

    console.print(f"[dim]  │  → {' '.join(cmd)}[/dim]")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        stdout_str = stdout.decode("utf-8", errors="ignore")
        stderr_str = stderr.decode("utf-8", errors="ignore")

        return (stdout_str, stderr_str, process.returncode)

    except asyncio.TimeoutError:
        # Kill the container on timeout
        console.print(f"[yellow]  │  ⚠ {tool_name} timed out — killing container[/yellow]")
        kill = await asyncio.create_subprocess_exec(
            "docker", "kill", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await kill.communicate()
        return ("", f"Timed out after {timeout}s", -1)
    except Exception as e:
        return ("", str(e), -1)


async def run_wpscan(target: str, extra_args: Optional[list[str]] = None) -> tuple[str, str, int]:
    """Run wpscan in Docker. Returns (stdout, stderr, return_code)."""
    args = [
        "--url", target,
        "--enumerate", "vp,vt,tt,cb,dbe",
        "--random-user-agent",
        "--no-banner",
        "--no-update",  # Skip update check for speed
    ]
    if extra_args:
        args.extend(extra_args)
    
    return await run_tool("wpscan", args, timeout=300)


async def run_nikto(target: str, extra_args: Optional[list[str]] = None) -> tuple[str, str, int]:
    """Run nikto in Docker. Returns (stdout, stderr, return_code)."""
    args = [
        f"-h {target}",
        "-Format", "json",
        "-nointeractive",
    ]
    if extra_args:
        args.extend(extra_args)
    
    return await run_tool("nikto", args, timeout=300)


async def run_nuclei(target: str, extra_args: Optional[list[str]] = None) -> tuple[str, str, int]:
    """Run nuclei in Docker. Returns (stdout, stderr, return_code)."""
    args = [
        "-u", target,
        "-silent",
    ]
    if extra_args:
        args.extend(extra_args)
    
    return await run_tool("nuclei", args, timeout=300)
