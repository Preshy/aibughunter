"""
AI Bug Hunter - API Usage Examples

This file demonstrates how to use the AI Bug Hunter API
inside other Python programs, scripts, or notebooks.
"""

import asyncio
from aibughunter.api import BugHunter, hunt, scan, query


async def example_basic_hunt():
    """Example: Run a full automated hunt."""
    print("=" * 70)
    print("Example 1: Full Automated Hunt")
    print("=" * 70)
    
    async with BugHunter(depth="standard") as hunter:
        results = await hunter.hunt("https://example.com")
        
        print(f"\nScan ID: {results['scan_id']}")
        print(f"Target: {results['target']}")
        print(f"Duration: {results['duration']:.1f}s")
        print(f"Total findings: {results['total_findings']}")
        
        if results['report_path']:
            print(f"Report: {results['report_path']}")


async def example_web_scan():
    """Example: Scan a web application."""
    print("\n" + "=" * 70)
    print("Example 2: Web Application Scan")
    print("=" * 70)
    
    async with BugHunter() as hunter:
        findings = await hunter.scan_web(
            "https://example.com",
            depth="aggressive",
        )
        
        print(f"\nFound {len(findings)} vulnerabilities:")
        for finding in findings[:5]:
            print(f"  [{finding['severity'].upper()}] {finding['title']}")


async def example_find_targets():
    """Example: Find bug bounty targets via dorking."""
    print("\n" + "=" * 70)
    print("Example 3: Find Targets via Google Dorking")
    print("=" * 70)
    
    async with BugHunter() as hunter:
        targets = await hunter.find_targets(
            categories=["exposed_panels", "api_endpoints"],
            max_results=20,
        )
        
        print(f"\nFound {len(targets)} potential targets:")
        for target in targets[:5]:
            print(f"  [{target['severity'].upper()}] {target['url']}")


async def example_recon():
    """Example: Perform reconnaissance."""
    print("\n" + "=" * 70)
    print("Example 4: Reconnaissance")
    print("=" * 70)
    
    async with BugHunter() as hunter:
        recon_data = await hunter.recon(
            "https://example.com",
            subdomains=True,
            techstack=True,
            endpoints=True,
        )
        
        print(f"\nReconnaissance complete:")
        print(f"  Subdomains: {len(recon_data.get('subdomains', []))}")
        print(f"  Endpoints: {len(recon_data.get('endpoints', []))}")
        print(f"  Technologies: {recon_data.get('technologies', {})}")


async def example_query_database():
    """Example: Query findings from database."""
    print("\n" + "=" * 70)
    print("Example 5: Query Database")
    print("=" * 70)
    
    hunter = BugHunter()
    
    # Get all HIGH severity findings
    high_findings = hunter.query_findings(severity="high")
    print(f"\nHIGH severity findings: {len(high_findings)}")
    
    # Get stats
    stats = hunter.get_stats()
    print(f"\nDatabase Stats:")
    print(f"  Total findings: {stats['total_findings']}")
    print(f"  By severity: {stats['by_severity']}")
    
    hunter.close()


async def example_convenience_functions():
    """Example: Use convenience functions."""
    print("\n" + "=" * 70)
    print("Example 6: Convenience Functions")
    print("=" * 70)
    
    # Quick scan
    findings = await scan("https://example.com", scan_type="web")
    print(f"\nQuick scan found {len(findings)} vulnerabilities")
    
    # Query findings
    all_findings = query(limit=10)
    print(f"Total findings in DB: {len(all_findings)}")


async def example_custom_workflow():
    """Example: Custom workflow with multiple steps."""
    print("\n" + "=" * 70)
    print("Example 7: Custom Workflow")
    print("=" * 70)
    
    targets = ["https://example.com", "https://example.org"]
    all_findings = []
    
    async with BugHunter() as hunter:
        for target in targets:
            print(f"\nScanning {target}...")
            
            # Recon
            recon = await hunter.recon(target, endpoints=True)
            print(f"  Found {len(recon.get('endpoints', []))} endpoints")
            
            # Scan
            findings = await hunter.scan_web(target, depth="quick")
            all_findings.extend(findings)
            print(f"  Found {len(findings)} vulnerabilities")
    
    print(f"\nTotal findings across all targets: {len(all_findings)}")


async def main():
    """Run all examples."""
    print("\n🎯 AI Bug Hunter - API Examples\n")
    
    try:
        await example_convenience_functions()
    except Exception as e:
        print(f"Skipped (no data yet): {e}")
    
    try:
        await example_query_database()
    except Exception as e:
        print(f"Skipped: {e}")
    
    # Uncomment to run (requires network access):
    # await example_basic_hunt()
    # await example_web_scan()
    # await example_find_targets()
    # await example_recon()
    # await example_custom_workflow()
    
    print("\n✅ Examples complete!")
    print("\n💡 To run full examples, uncomment the lines in main()")


if __name__ == "__main__":
    asyncio.run(main())
