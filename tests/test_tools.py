"""Tests for tools management."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from aibughunter.tools.manager import ToolManager, SecurityTool
from aibughunter.tools.kali_tools import KaliToolsManager, KaliTool, ToolCategory


class TestSecurityTool:
    """Test SecurityTool model."""
    
    def test_create_tool(self):
        """Test creating a security tool."""
        tool = SecurityTool(
            name="nmap",
            category="recon",
            description="Network scanner",
            install_command="apt install nmap",
            check_command="nmap --version",
        )
        
        assert tool.name == "nmap"
        assert tool.installed is False
        assert tool.version is None


class TestToolManager:
    """Test tool management."""
    
    @pytest.fixture
    def tool_manager(self, tmp_path):
        """Create tool manager with temporary directory."""
        return ToolManager(tools_dir=str(tmp_path / "tools"))
    
    def test_initialization(self, tool_manager):
        """Test manager initializes."""
        assert len(tool_manager.tools) > 0
    
    def test_list_tools(self, tool_manager):
        """Test listing tools."""
        tools = tool_manager.list_tools()
        
        assert len(tools) > 0
        assert isinstance(tools[0], SecurityTool)
    
    def test_registered_tools(self, tool_manager):
        """Test expected tools are registered."""
        tool_names = [t.name for t in tool_manager.tools]
        
        expected_tools = ["nmap", "httpx", "subfinder", "sqlmap", "nuclei", "ffuf"]
        for expected in expected_tools:
            assert expected in tool_names
    
    @pytest.mark.asyncio
    async def test_ensure_tools(self, tool_manager):
        """Test ensuring tools are available."""
        with patch.object(tool_manager, 'install_tool', new_callable=AsyncMock()):
            await tool_manager.ensure_tools(["nmap"])
            # Should not raise
    
    @pytest.mark.asyncio
    async def test_install_tool_unknown(self, tool_manager):
        """Test installing unknown tool raises error."""
        with pytest.raises(ValueError):
            await tool_manager.install_tool("nonexistent-tool")
    
    @pytest.mark.asyncio
    async def test_install_tool_success(self, tool_manager):
        """Test successful tool installation."""
        with patch("asyncio.create_subprocess_shell") as mock_shell:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"installed", b"")
            mock_shell.return_value = mock_process
            
            await tool_manager.install_tool("nmap")
            
            tool = next(t for t in tool_manager.tools if t.name == "nmap")
            assert tool.installed is True
    
    @pytest.mark.asyncio
    async def test_install_tool_failure(self, tool_manager):
        """Test failed tool installation."""
        with patch("asyncio.create_subprocess_shell") as mock_shell:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"error")
            mock_shell.return_value = mock_process
            
            await tool_manager.install_tool("nmap")
            # Should not raise, but tool should not be installed
    
    def test_check_installed_tools(self, tool_manager):
        """Test checking installed tools."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="version 1.0", stdout="")
            tool_manager._check_installed_tools()
            
            # All tools should be marked as installed in mock
            for tool in tool_manager.tools:
                assert tool.installed is True


class TestKaliToolsManager:
    """Test Kali tools management."""
    
    @pytest.fixture
    def kali_manager(self, tmp_path):
        """Create Kali tools manager with temporary directory."""
        return KaliToolsManager(tools_dir=str(tmp_path / "kali-tools"))
    
    def test_initialization(self, kali_manager):
        """Test manager initializes."""
        assert len(kali_manager.KALI_TOOLS) > 0
    
    def test_kali_tools_registered(self, kali_manager):
        """Test expected Kali tools are registered."""
        tool_names = list(kali_manager.KALI_TOOLS.keys())
        
        expected = ["nmap", "sqlmap", "metasploit", "burpsuite", "nikto", "hydra"]
        for name in expected:
            assert name in tool_names
    
    def test_tool_categories(self, kali_manager):
        """Test tools have correct categories."""
        nmap = kali_manager.KALI_TOOLS["nmap"]
        assert nmap.category == ToolCategory.RECON
        
        sqlmap = kali_manager.KALI_TOOLS["sqlmap"]
        assert sqlmap.category == ToolCategory.WEB_APP
        
        metasploit = kali_manager.KALI_TOOLS["metasploit"]
        assert metasploit.category == ToolCategory.EXPLOITATION
    
    def test_list_tools(self, kali_manager):
        """Test listing Kali tools."""
        tools = kali_manager.list_tools()
        assert len(tools) > 0
    
    def test_list_tools_by_category(self, kali_manager):
        """Test filtering by category."""
        recon_tools = kali_manager.list_tools(category=ToolCategory.RECON)
        
        assert len(recon_tools) > 0
        assert all(t.category == ToolCategory.RECON for t in recon_tools)
        assert any(t.name == "nmap" for t in recon_tools)
    
    def test_list_installed_only(self, kali_manager):
        """Test listing only installed tools."""
        with patch.object(kali_manager, '_check_installed'):
            # Mock all as not installed
            for tool in kali_manager.KALI_TOOLS.values():
                tool.installed = False
            
            tools = kali_manager.list_tools(installed_only=True)
            assert len(tools) == 0
    
    def test_display_tools(self, kali_manager, capsys):
        """Test displaying tools."""
        kali_manager.display_tools()
        # Should not crash
    
    def test_search_tools(self, kali_manager):
        """Test searching for tools."""
        results = kali_manager.search_tools("sql")
        
        assert len(results) > 0
        assert any("sql" in t.name.lower() for t in results)
        assert any("sql" in t.description.lower() for t in results)
    
    def test_search_tools_no_results(self, kali_manager):
        """Test search with no matches."""
        results = kali_manager.search_tools("zzzznonexistent")
        assert len(results) == 0
    
    def test_get_tool_help(self, kali_manager):
        """Test getting tool help."""
        help_text = kali_manager.get_tool_help("nmap")
        
        assert "nmap" in help_text
        assert "Network discovery" in help_text
    
    def test_get_tool_help_unknown(self, kali_manager):
        """Test help for unknown tool."""
        help_text = kali_manager.get_tool_help("nonexistent")
        assert "Unknown tool" in help_text
    
    @pytest.mark.asyncio
    async def test_install_tool_success(self, kali_manager):
        """Test successful tool installation."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"installed", b"")
            mock_exec.return_value = mock_process
            
            result = await kali_manager.install_tool("nmap")
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_install_tool_failure(self, kali_manager):
        """Test failed tool installation."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"error")
            mock_exec.return_value = mock_process
            
            result = await kali_manager.install_tool("nmap")
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_install_tool_unknown(self, kali_manager):
        """Test installing unknown tool."""
        result = await kali_manager.install_tool("nonexistent-tool")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_run_tool(self, kali_manager):
        """Test running a tool."""
        # Mark tool as installed
        kali_manager.KALI_TOOLS["nmap"].installed = True
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"scan results", b"")
            mock_exec.return_value = mock_process
            
            result = await kali_manager.run_tool("nmap", ["-sV", "target.com"])
            
            assert result["tool"] == "nmap"
            assert result["return_code"] == 0
            assert result["stdout"] == "scan results"
    
    @pytest.mark.asyncio
    async def test_run_tool_not_installed(self, kali_manager):
        """Test running uninstalled tool."""
        kali_manager.KALI_TOOLS["nmap"].installed = False
        
        with pytest.raises(RuntimeError) as exc_info:
            await kali_manager.run_tool("nmap", ["-sV"])
        
        assert "not installed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_run_tool_timeout(self, kali_manager):
        """Test tool execution timeout."""
        import asyncio
        kali_manager.KALI_TOOLS["nmap"].installed = True
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.side_effect = asyncio.TimeoutError()
            mock_exec.return_value = mock_process
            
            result = await kali_manager.run_tool("nmap", ["-sV"], timeout=1)
            
            assert result["return_code"] == -1
            assert result["error"] == "Timeout"
    
    @pytest.mark.asyncio
    async def test_run_tool_with_output_file(self, kali_manager, tmp_path):
        """Test running tool with output file."""
        kali_manager.KALI_TOOLS["nmap"].installed = True
        
        output_file = tmp_path / "scan.txt"
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process
            
            result = await kali_manager.run_tool(
                "nmap",
                ["-sV"],
                output_file=str(output_file),
            )
            
            assert result["output_file"] == str(output_file)
    
    def test_usage_statistics(self, kali_manager):
        """Test usage statistics tracking."""
        kali_manager.KALI_TOOLS["nmap"].installed = True
        
        # Run tool multiple times
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process
            
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                kali_manager.run_tool("nmap", ["-sV"])
            )
        
        # Check stats
        assert "nmap" in kali_manager.tools
        assert kali_manager.tools["nmap"]["use_count"] == 1
