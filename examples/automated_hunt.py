"""
Example: Automated Bug Hunting Script

This script demonstrates how to use AI Bug Hunter programmatically
for automated bug bounty hunting.
"""

import asyncio
from aibughunter.scanners.dork_finder import GoogleDorkFinder
from aibughunter.scanners.web_scanner import WebVulnerabilityScanner
from aibughunter.core.scope import ScopeManager
from aibughunter.reports.generator import ReportGenerator


async def automated_hunt():
    """Automated bug hunting workflow."""
    
    print("🎯 Starting Automated Bug Hunt\n")
    
    # Step 1: Find potential targets using Google Dorking
    print("📍 Step 1: Finding potential targets...")
    dork_finder = GoogleDorkFinder(output_dir="./recon/dorks", delay=1.5)
    
    dork_results = await dork_finder.find_targets_for_bounty(
        max_results=50,
    )
    
    print(f"✓ Found {len(dork_results)} potential targets\n")
    
    # Display top results
    dork_finder.display_results(limit=10)
    
    await dork_finder.close()
    
    # Step 2: Add promising targets to scope
    print("\n📍 Step 2: Adding targets to scope...")
    scope_manager = ScopeManager()
    
    # Example: Add a target (replace with actual target from dork results)
    # target = dork_results[0].url
    # scope_manager.add_target(target, scope_type="in", program="hackerone")
    
    # Step 3: Scan a target
    print("\n📍 Step 3: Scanning target...")
    # Replace with your authorized target
    target_url = "https://example.com"
    
    scanner = WebVulnerabilityScanner(
        target=target_url,
        depth="standard",
        output_dir="./reports",
    )
    
    findings = await scanner.run_scan()
    print(f"✓ Found {len(findings)} vulnerabilities\n")
    
    await scanner.close()
    
    # Step 4: Generate report
    print("📍 Step 4: Generating report...")
    report_gen = ReportGenerator(
        output_dir="./reports",
        template="hackerone",
        output_format="markdown",
    )
    
    await report_gen.generate_from_findings(findings, scan_id="automated_hunt_001")
    
    print("\n✅ Bug hunt complete!")
    print("📁 Check ./reports for generated reports")


if __name__ == "__main__":
    asyncio.run(automated_hunt())
