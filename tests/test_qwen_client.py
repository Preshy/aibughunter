"""Tests for Qwen CLI client integration."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from aibughunter.ai.qwen_client import QwenCLIClient


@pytest.fixture
def client():
    """Create a Qwen CLI client for testing."""
    return QwenCLIClient(
        model="test-model",
        yolo=True,
        approval_mode="yolo",
        max_session_turns=5,
    )


@pytest.fixture
def mock_qwen_output():
    """Mock JSON stream output from qwen CLI."""
    return json.dumps([
        {
            "type": "result",
            "result": "Test response from Qwen",
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
    ]).encode()


class TestQwenCLIClient:
    """Test Qwen CLI client functionality."""
    
    def test_client_initialization(self):
        """Test client initializes with default values."""
        client = QwenCLIClient()
        assert client.model is None
        assert client.yolo is False
        assert client.approval_mode == "yolo"
        assert client.max_session_turns == 10
        assert client.workspace == Path.cwd()
    
    def test_client_initialization_with_params(self):
        """Test client initializes with custom parameters."""
        client = QwenCLIClient(
            model="coder-model",
            yolo=True,
            max_session_turns=20,
        )
        assert client.model == "coder-model"
        assert client.yolo is True
        assert client.max_session_turns == 20
    
    @pytest.mark.asyncio
    async def test_ask_simple_prompt(self, client, mock_qwen_output):
        """Test asking a simple prompt."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_qwen_output, b"")
            mock_exec.return_value = mock_process
            
            result = await client.ask("What is 2+2?")
            
            assert result == "Test response from Qwen"
            # Verify command was built correctly
            call_args = mock_exec.call_args[0]
            assert "qwen" in call_args
            assert "-p" in call_args
            assert "--approval-mode" in call_args
            assert "yolo" in call_args
    
    @pytest.mark.asyncio
    async def test_ask_with_system_prompt(self, client, mock_qwen_output):
        """Test asking with system prompt."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_qwen_output, b"")
            mock_exec.return_value = mock_process
            
            await client.ask(
                "Analyze this vulnerability",
                system_prompt="You are a security researcher",
            )
            
            call_args = mock_exec.call_args[0]
            assert "--system-prompt" in call_args
    
    @pytest.mark.asyncio
    async def test_ask_timeout(self, client):
        """Test timeout handling."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            import asyncio
            mock_process = AsyncMock()
            mock_process.communicate.side_effect = asyncio.TimeoutError()
            mock_exec.return_value = mock_process
            
            with pytest.raises(TimeoutError):
                await client.ask("Slow prompt", timeout=1)
    
    @pytest.mark.asyncio
    async def test_ask_with_tools(self, client):
        """Test ask_with_tools builds correct command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b'[]', b"")
            mock_exec.return_value = mock_process
            
            result = await client.ask_with_tools("Run nmap scan")
            
            assert isinstance(result, dict)
            assert "raw_output" in result
            assert "text_response" in result
            assert "tool_calls" in result
            
            call_args = mock_exec.call_args[0]
            # Should have yolo mode for tool usage
            assert "yolo" in call_args
    
    @pytest.mark.asyncio
    async def test_parse_stream_response(self, client):
        """Test parsing JSON stream output."""
        output = json.dumps([
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "Hello!"}]}},
            {"type": "result", "result": "Final answer"},
        ]).encode()
        
        result = client._parse_stream_response(output)
        assert result == "Final answer"
    
    @pytest.mark.asyncio
    async def test_parse_stream_response_fallback(self, client):
        """Test fallback to raw output if parsing fails."""
        output = b"Not valid JSON at all"
        result = client._parse_stream_response(output)
        assert result == "Not valid JSON at all"
    
    def test_build_command_simple(self, client):
        """Test command building without tools."""
        cmd = client._build_command("test prompt")
        
        assert cmd[0] == "qwen"
        assert "-p" in cmd
        assert "test prompt" in cmd
        assert "-o" in cmd
        assert "json" in cmd
        assert "--approval-mode" in cmd
        assert "yolo" in cmd
    
    def test_build_command_with_model(self, client):
        """Test command includes model."""
        client.model = "coder-model"
        cmd = client._build_command("test")
        
        assert "-m" in cmd
        assert "coder-model" in cmd
    
    def test_build_command_with_system_prompt(self, client):
        """Test command includes system prompt."""
        cmd = client._build_command(
            "test",
            system_prompt="You are a hacker",
        )
        
        assert "--system-prompt" in cmd
        assert "You are a hacker" in cmd
    
    def test_build_command_with_tools(self, client):
        """Test command building for tool usage."""
        cmd = client._build_command_with_tools("scan target")
        
        assert "qwen" in cmd
        assert "--approval-mode" in cmd
        assert "yolo" in cmd
        assert "--include-partial-messages" in cmd
    
    @pytest.mark.asyncio
    async def test_analyze_vulnerability(self, client):
        """Test vulnerability analysis."""
        json_response = json.dumps({
            "severity": "high",
            "cvss_score": 7.5,
            "title": "SQL Injection",
            "description": "Found SQLi",
        })
        
        mock_output = json.dumps([
            {"type": "result", "result": f"```json\n{json_response}\n```"}
        ]).encode()
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_output, b"")
            mock_exec.return_value = mock_process
            
            result = await client.analyze_vulnerability(
                vuln_type="sql_injection",
                details="Parameter is vulnerable",
            )
            
            assert result["severity"] == "high"
            assert result["cvss_score"] == 7.5
    
    @pytest.mark.asyncio
    async def test_generate_code(self, client):
        """Test code generation."""
        code_response = '''```python
import requests

def scan_target(url):
    """Scan target for vulnerabilities."""
    response = requests.get(url)
    return response.status_code
```'''
        
        mock_output = json.dumps([
            {"type": "result", "result": code_response}
        ]).encode()
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_output, b"")
            mock_exec.return_value = mock_process
            
            result = await client.generate_code(
                "Create a port scanner",
                language="python",
            )
            
            assert "import requests" in result or "def scan_target" in result
    
    @pytest.mark.asyncio
    async def test_suggest_next_steps(self, client):
        """Test next steps suggestion."""
        steps_response = "1. Test for XSS\n2. Check SQL injection\n3. Look for IDOR"
        
        mock_output = json.dumps([
            {"type": "result", "result": steps_response}
        ]).encode()
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_output, b"")
            mock_exec.return_value = mock_process
            
            result = await client.suggest_next_steps(
                current_findings=[],
                target_info="https://example.com",
            )
            
            assert len(result) > 0
            assert any("XSS" in step for step in result)
    
    @pytest.mark.asyncio
    async def test_qwen_error_handling(self, client):
        """Test error handling when qwen fails."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Error: model not found")
            mock_exec.return_value = mock_process
            
            with pytest.raises(RuntimeError) as exc_info:
                await client.ask("test")
            
            assert "Qwen CLI error" in str(exc_info.value)
    
    def test_parse_full_response(self, client):
        """Test parsing full response with stderr."""
        stdout = json.dumps([
            {"type": "result", "result": "Success", "usage": {"tokens": 100}}
        ]).encode()
        stderr = b"Warning: deprecated"
        
        result = client._parse_full_response(stdout, stderr)
        
        assert result["text_response"] == "Success"
        assert result["stderr"] == "Warning:deprecated" if isinstance(result["stderr"], str) else stderr.decode()
        assert result["usage"]["tokens"] == 100
