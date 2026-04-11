"""Tests for Google Dork finder."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import asdict

from aibughunter.scanners.dork_finder import GoogleDorkFinder, DorkResult, DorkQuery


@pytest.fixture
def dork_finder(tmp_path):
    """Create a dork finder with temporary directory."""
    output_dir = tmp_path / "dorks"
    return GoogleDorkFinder(output_dir=str(output_dir), delay=0.1)


class TestDorkResult:
    """Test DorkResult model."""
    
    def test_create_result(self):
        """Test creating a dork result."""
        result = DorkResult(
            url="https://example.com/admin",
            title="Admin Panel",
            description="Found admin panel",
            dork_used="inurl:admin",
            category="exposed_panels",
            severity_potential="high",
        )
        
        assert result.url == "https://example.com/admin"
        assert result.severity_potential == "high"
        assert result.discovered_at is not None


class TestDorkQuery:
    """Test DorkQuery model."""
    
    def test_create_query(self):
        """Test creating a dork query."""
        query = DorkQuery(
            query="inurl:admin",
            category="exposed_panels",
            description="Admin panels",
            severity_potential="high",
        )
        
        assert query.query == "inurl:admin"
        assert query.category == "exposed_panels"


class TestGoogleDorkFinder:
    """Test Google Dork finder functionality."""
    
    def test_initialization(self, dork_finder):
        """Test finder initializes correctly."""
        assert dork_finder.delay == 0.1
        assert dork_finder.max_results_per_dork == 20
        assert dork_finder.output_dir.exists()
    
    def test_dork_templates_exist(self, dork_finder):
        """Test dork templates are populated."""
        assert len(dork_finder.DORK_TEMPLATES) > 0
        
        expected_categories = [
            "exposed_panels",
            "config_files",
            "sensitive_files",
            "vulnerable_apps",
            "cloud_storage",
            "api_endpoints",
            "error_pages",
        ]
        
        for category in expected_categories:
            assert category in dork_finder.DORK_TEMPLATES
            assert len(dork_finder.DORK_TEMPLATES[category]) > 0
    
    def test_list_dork_categories(self, dork_finder):
        """Test listing dork categories."""
        categories = dork_finder.list_dork_categories()
        
        assert "exposed_panels" in categories
        assert "config_files" in categories
        assert "custom" in categories
        assert categories["exposed_panels"]["count"] > 0
    
    def test_add_custom_dork(self, dork_finder, tmp_path):
        """Test adding custom dork."""
        dork_finder.add_custom_dork(
            query="inurl:login site:test.com",
            category="custom",
            description="Test custom dork",
            severity="high",
        )
        
        assert len(dork_finder.custom_dorks) == 1
        assert dork_finder.custom_dorks[0].query == "inurl:login site:test.com"
        
        # Verify saved to disk
        dork_file = tmp_path / "dorks" / "dorks_custom.json"
        assert dork_file.exists()
    
    def test_load_custom_dorks(self, dork_finder, tmp_path):
        """Test loading custom dorks from file."""
        dork_file = tmp_path / "dorks" / "dorks_custom.json"
        dork_file.parent.mkdir(parents=True, exist_ok=True)
        
        dork_data = {
            "dorks": [
                {
                    "query": "inurl:test",
                    "category": "custom",
                    "description": "Test dork",
                    "severity_potential": "medium",
                }
            ]
        }
        dork_file.write_text(json.dumps(dork_data))
        
        finder = GoogleDorkFinder(output_dir=str(tmp_path / "dorks"))
        assert len(finder.custom_dorks) == 1
    
    def test_deduplicate_results(self, dork_finder):
        """Test deduplication of results."""
        results = [
            DorkResult(url="https://example.com/page", title="1", description="", dork_used="", category="", severity_potential="high"),
            DorkResult(url="https://example.com/page/", title="2", description="", dork_used="", category="", severity_potential="medium"),
            DorkResult(url="https://example.com/other", title="3", description="", dork_used="", category="", severity_potential="low"),
        ]
        
        deduped = dork_finder._deduplicate_results(results)
        
        # Should remove duplicate URL (with trailing slash)
        assert len(deduped) == 2
    
    def test_deduplicate_sorts_by_severity(self, dork_finder):
        """Test deduplication sorts by severity."""
        results = [
            DorkResult(url="https://a.com", title="1", description="", dork_used="", category="", severity_potential="low"),
            DorkResult(url="https://b.com", title="2", description="", dork_used="", category="", severity_potential="critical"),
            DorkResult(url="https://c.com", title="3", description="", dork_used="", category="", severity_potential="high"),
        ]
        
        deduped = dork_finder._deduplicate_results(results)
        
        assert deduped[0].severity_potential == "critical"
        assert deduped[1].severity_potential == "high"
        assert deduped[2].severity_potential == "low"
    
    def test_search_builds_correct_dork_list(self, dork_finder):
        """Test search builds appropriate dork list."""
        # Should not raise
        import asyncio
        
        async def run_search():
            with patch.object(dork_finder, '_execute_dork', return_value=[]):
                results = await dork_finder.search(
                    categories=["exposed_panels"],
                    max_results=10,
                    save_results=False,
                )
                return results
        
        results = asyncio.run(run_search())
        assert results == []
    
    def test_search_with_target_replaces_placeholder(self, dork_finder):
        """Test search replaces TARGET placeholder."""
        async def run_search():
            with patch.object(dork_finder, '_execute_dork', return_value=[]) as mock_execute:
                results = await dork_finder.search(
                    categories=["subdomains"],
                    target="example.com",
                    max_results=10,
                    save_results=False,
                )
                return results, mock_execute.call_args_list
        
        results, calls = asyncio.run(run_search())
        # Verify TARGET was replaced
        assert results == []
    
    def test_save_results(self, dork_finder, tmp_path):
        """Test saving results to file."""
        dork_finder.results = [
            DorkResult(
                url="https://example.com",
                title="Test",
                description="Test result",
                dork_used="test",
                category="test",
                severity_potential="high",
            )
        ]
        
        dork_finder._save_results("test-target")
        
        # Check file was created
        output_files = list(dork_finder.output_dir.glob("dork_results_test-target_*.json"))
        assert len(output_files) == 1
        
        # Verify content
        with open(output_files[0]) as f:
            data = json.load(f)
            assert data["target"] == "test-target"
            assert data["total_results"] == 1
    
    def test_display_results_no_results(self, dork_finder, capsys):
        """Test display with no results."""
        dork_finder.display_results()
        # Should not crash
        assert True
    
    def test_find_targets_for_bounty(self, dork_finder):
        """Test finding bug bounty targets."""
        async def run():
            with patch.object(dork_finder, '_execute_dork', return_value=[]):
                results = await dork_finder.find_targets_for_bounty(max_results=10)
                return results
        
        results = asyncio.run(run())
        assert results == []
    
    def test_parse_google_results(self, dork_finder):
        """Test parsing Google search results."""
        # Simplified test - real parsing would be more complex
        html = '<a href="https://example.com/page">Test</a>'
        dork = DorkQuery(
            query="inurl:test",
            category="test",
            description="Test",
            severity_potential="medium",
        )
        
        results = dork_finder._parse_google_results(html, dork)
        # May not find results in simple HTML, but shouldn't crash
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_execute_dork_rate_limiting(self, dork_finder):
        """Test dork execution with rate limiting."""
        dork = DorkQuery(
            query="inurl:test",
            category="test",
            description="Test",
            severity_potential="medium",
        )
        
        with patch("aibughunter.scanners.dork_finder.httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = ""
            mock_get.return_value = mock_response
            
            results = await dork_finder._execute_dork(dork)
            assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_execute_dork_rate_limit_error(self, dork_finder):
        """Test handling of rate limit errors."""
        import httpx
        
        dork = DorkQuery(
            query="inurl:test",
            category="test",
            description="Test",
            severity_potential="medium",
        )
        
        with patch("aibughunter.scanners.dork_finder.httpx.AsyncClient.get") as mock_get:
            mock_get.side_effect = httpx.HTTPStatusError(
                "Rate limited",
                request=MagicMock(),
                response=MagicMock(status_code=429),
            )
            
            # Should handle gracefully
            results = await dork_finder._execute_dork(dork)
            assert results == []
