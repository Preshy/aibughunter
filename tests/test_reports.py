"""Tests for report generation."""

import json
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from aibughunter.reports.generator import ReportGenerator, FindingStore
from aibughunter.reports.poc_generator import POCGenerator
from aibughunter.reports.exporter import FindingsExporter


@pytest.fixture
def report_generator(tmp_path):
    """Create report generator with temporary directory."""
    return ReportGenerator(
        output_dir=str(tmp_path / "reports"),
        template="hackerone",
        output_format="markdown",
    )


@pytest.fixture
def sample_finding():
    """Create a sample vulnerability finding."""
    return {
        "id": "VULN-001",
        "type": "sql_injection",
        "severity": "critical",
        "title": "SQL Injection in login form",
        "description": "The login form is vulnerable to SQL injection",
        "url": "https://example.com/login",
        "parameter": "username",
        "target": "https://example.com",
        "timestamp": datetime.now().isoformat(),
        "impact": "Full database compromise",
        "steps": ["Navigate to login", "Inject payload", "Observe bypass"],
        "remediation": "Use parameterized queries",
    }


@pytest.fixture
def finding_store(tmp_path):
    """Create finding store with temporary directory."""
    store = FindingStore(data_dir=str(tmp_path / "data"))
    return store


class TestFindingStore:
    """Test finding storage."""
    
    def test_save_finding(self, finding_store, sample_finding):
        """Test saving a finding."""
        finding_store.save_finding(sample_finding)
        
        findings = finding_store.get_all_findings()
        assert len(findings) == 1
        assert findings[0]["id"] == "VULN-001"
    
    def test_get_finding(self, finding_store, sample_finding):
        """Test retrieving a specific finding."""
        finding_store.save_finding(sample_finding)
        
        finding = finding_store.get_finding("VULN-001")
        assert finding is not None
        assert finding["title"] == "SQL Injection in login form"
    
    def test_get_finding_not_found(self, finding_store):
        """Test retrieving non-existent finding."""
        finding = finding_store.get_finding("NONEXISTENT")
        assert finding is None
    
    def test_get_findings_by_scan(self, finding_store):
        """Test filtering findings by scan."""
        findings = [
            {"id": "V1", "scan_id": "scan1", "severity": "high"},
            {"id": "V2", "scan_id": "scan1", "severity": "medium"},
            {"id": "V3", "scan_id": "scan2", "severity": "low"},
        ]
        
        for finding in findings:
            finding_store.save_finding(finding)
        
        scan1_findings = finding_store.get_findings_by_scan("scan1")
        assert len(scan1_findings) == 2
    
    def test_get_findings_by_severity(self, finding_store):
        """Test filtering by severity."""
        findings = [
            {"id": "V1", "severity": "critical"},
            {"id": "V2", "severity": "high"},
            {"id": "V3", "severity": "medium"},
        ]
        
        for finding in findings:
            finding_store.save_finding(finding)
        
        high_plus = finding_store.get_all_findings(min_severity="high")
        assert len(high_plus) == 2  # critical and high
    
    def test_list_findings_with_filters(self, finding_store):
        """Test listing findings with various filters."""
        findings = [
            {"id": "V1", "status": "new", "severity": "high"},
            {"id": "V2", "status": "reported", "severity": "medium"},
            {"id": "V3", "status": "new", "severity": "low"},
        ]
        
        for finding in findings:
            finding_store.save_finding(finding)
        
        new_findings = finding_store.list_findings(status="new")
        assert len(new_findings) == 2
    
    def test_persistence(self, finding_store, sample_finding):
        """Test findings are persisted to disk."""
        finding_store.save_finding(sample_finding)
        
        # Create new instance
        new_store = FindingStore(data_dir=finding_store.data_dir)
        assert len(new_store.get_all_findings()) == 1


class TestReportGenerator:
    """Test report generation."""
    
    @pytest.mark.asyncio
    async def test_generate_single_report(self, report_generator, sample_finding, capsys):
        """Test generating a single finding report."""
        await report_generator.generate_from_findings([sample_finding], scan_id="test-scan")
        
        # Check file was created
        report_files = list(report_generator.output_dir.glob("report_VULN-001_*.md"))
        assert len(report_files) == 1
        
        # Verify content
        content = report_files[0].read_text()
        assert "SQL Injection in login form" in content
        assert "critical" in content.lower()
    
    @pytest.mark.asyncio
    async def test_generate_summary_report(self, report_generator, capsys):
        """Test generating summary report for multiple findings."""
        findings = [
            {"id": "V1", "severity": "high", "title": "Finding 1", "type": "xss", "target": "target.com", "description": "Desc 1"},
            {"id": "V2", "severity": "medium", "title": "Finding 2", "type": "csrf", "target": "target.com", "description": "Desc 2"},
        ]
        
        await report_generator.generate_from_findings(findings, scan_id="test-scan")
        
        report_files = list(report_generator.output_dir.glob("report_scan_test-scan_*.md"))
        assert len(report_files) == 1
        
        content = report_files[0].read_text()
        assert "Security Scan Summary Report" in content
        assert "Finding 1" in content
        assert "Finding 2" in content
    
    @pytest.mark.asyncio
    async def test_generate_from_empty_findings(self, report_generator, capsys):
        """Test generating report from no findings."""
        with patch("aibughunter.reports.finding_store.FindingStore") as mock_store:
            mock_store.return_value.get_all_findings.return_value = []
            
            await report_generator.generate()
            # Should print warning but not crash
    
    def test_single_report_template(self, report_generator, sample_finding):
        """Test single report template rendering."""
        report = report_generator._generate_single_report(sample_finding)
        
        assert "Vulnerability Report" in report
        assert "SQL Injection in login form" in report
        assert "CRITICAL" in report
        assert "Steps to Reproduce" in report
    
    def test_summary_report_template(self, report_generator):
        """Test summary report template."""
        findings = [
            {"id": "V1", "severity": "high", "title": "High Severity", "type": "xss", "target": "target.com", "description": "High sev finding"},
            {"id": "V2", "severity": "low", "title": "Low Severity", "type": "info", "target": "target.com", "description": "Low sev finding"},
        ]
        
        report = report_generator._generate_summary_report(findings, "scan-123")
        
        assert "Summary Report" in report
        assert "Executive Summary" in report
        assert "Findings Overview" in report


class TestPOCGenerator:
    """Test POC generation."""
    
    @pytest.fixture
    def poc_generator(self, tmp_path):
        """Create POC generator with temporary directory."""
        return POCGenerator(output_dir=str(tmp_path / "pocs"))
    
    @pytest.mark.asyncio
    async def test_generate_poc_sql_injection(self, poc_generator, finding_store, capsys):
        """Test POC generation for SQL injection."""
        finding = {
            "id": "SQLI-001",
            "type": "sql_injection",
            "severity": "critical",
            "title": "SQL Injection",
            "description": "Parameter is vulnerable",
            "url": "https://example.com/page?id=1",
            "parameter": "id",
            "target": "https://example.com",
        }
        
        finding_store.save_finding(finding)
        
        await poc_generator.generate_poc("SQLI-001")
        
        poc_files = list(poc_generator.output_dir.glob("poc_SQLI-001_*.md"))
        assert len(poc_files) == 1
        
        content = poc_files[0].read_text()
        assert "SQL Injection" in content
        assert "Steps to Reproduce" in content
        assert "sqlmap" in content
    
    @pytest.mark.asyncio
    async def test_generate_poc_xss(self, poc_generator, finding_store):
        """Test POC generation for XSS."""
        finding = {
            "id": "XSS-001",
            "type": "cross-site_scripting",
            "severity": "high",
            "title": "XSS Vulnerability",
            "description": "Reflected XSS found",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "target": "https://example.com",
        }
        
        finding_store.save_finding(finding)
        
        await poc_generator.generate_poc("XSS-001")
        
        poc_files = list(poc_generator.output_dir.glob("poc_XSS-001_*.md"))
        assert len(poc_files) == 1
    
    @pytest.mark.asyncio
    async def test_generate_poc_not_found(self, poc_generator, capsys):
        """Test POC generation for non-existent finding."""
        await poc_generator.generate_poc("NONEXISTENT")
        # Should print error but not crash
    
    def test_get_reproduction_steps_sql(self, poc_generator):
        """Test reproduction steps for SQL injection."""
        finding = {"url": "https://example.com/page", "parameter": "id"}
        steps = poc_generator._get_reproduction_steps("sql_injection", finding)
        
        assert "sqlmap" in steps
        assert "id" in steps
    
    def test_get_impact_description(self, poc_generator):
        """Test impact descriptions exist."""
        for vuln_type in ["sql_injection", "cross-site_scripting", "missing_security_header"]:
            impact = poc_generator._get_impact_description(vuln_type)
            assert len(impact) > 0
    
    def test_get_remediation(self, poc_generator):
        """Test remediation advice exists."""
        for vuln_type in ["sql_injection", "cross-site_scripting"]:
            remediation = poc_generator._get_remediation(vuln_type)
            assert len(remediation) > 0


class TestFindingsExporter:
    """Test findings export."""
    
    @pytest.fixture
    def exporter(self, tmp_path):
        """Create exporter with temporary directory."""
        return FindingsExporter(output_dir=str(tmp_path / "exports"))
    
    @pytest.mark.asyncio
    async def test_export_json(self, exporter, finding_store):
        """Test exporting to JSON."""
        finding_store.save_finding({
            "id": "V1",
            "severity": "high",
            "title": "Test Finding",
        })
        
        output_file = exporter.output_dir / "test.json"
        await exporter.export(
            format="json",
            output_path=str(output_file),
        )
        
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["total_findings"] == 1
    
    @pytest.mark.asyncio
    async def test_export_csv(self, exporter, finding_store):
        """Test exporting to CSV."""
        finding_store.save_finding({
            "id": "V1",
            "type": "xss",
            "severity": "high",
            "title": "Test Finding",
            "description": "Test description",
            "target": "example.com",
            "timestamp": datetime.now().isoformat(),
        })
        
        output_file = exporter.output_dir / "test.csv"
        await exporter.export(
            format="csv",
            output_path=str(output_file),
        )
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "id,type,severity" in content or "V1" in content
    
    @pytest.mark.asyncio
    async def test_export_xml(self, exporter, finding_store):
        """Test exporting to XML."""
        finding_store.save_finding({
            "id": "V1",
            "severity": "high",
            "title": "Test Finding",
        })
        
        output_file = exporter.output_dir / "test.xml"
        await exporter.export(
            format="xml",
            output_path=str(output_file),
        )
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "<?xml" in content
        assert "<findings>" in content
        assert "<id>V1</id>" in content
    
    @pytest.mark.asyncio
    async def test_export_no_findings(self, exporter, capsys):
        """Test exporting with no findings."""
        output_file = exporter.output_dir / "empty.json"
        await exporter.export(
            format="json",
            output_path=str(output_file),
        )
        # Should print warning but not crash
    
    @pytest.mark.asyncio
    async def test_export_invalid_format(self, exporter, finding_store):
        """Test exporting with invalid format."""
        with pytest.raises(ValueError):
            await exporter.export(
                format="invalid",
                output_path="test.invalid",
            )
    
    @pytest.mark.asyncio
    async def test_export_by_scan_id(self, exporter, finding_store):
        """Test exporting findings from specific scan."""
        finding_store.save_finding({"id": "V1", "scan_id": "scan1"})
        finding_store.save_finding({"id": "V2", "scan_id": "scan2"})
        
        output_file = exporter.output_dir / "scan1.json"
        await exporter.export(
            format="json",
            output_path=str(output_file),
            scan_id="scan1",
        )
        
        data = json.loads(output_file.read_text())
        assert data["total_findings"] == 1
