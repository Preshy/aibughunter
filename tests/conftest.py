"""Shared pytest fixtures and configuration."""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.fixture
def mock_qwen_cli():
    """Mock Qwen CLI subprocess calls."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_exec.return_value = mock_process
        yield mock_exec


@pytest.fixture
def mock_httpx_client():
    """Mock HTTPX async client."""
    with patch("aibughunter.scanners.recon_scanner.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get = AsyncMock()
        mock_instance.post = AsyncMock()
        mock_instance.aclose = AsyncMock()
        mock_client.return_value = mock_instance
        yield mock_instance
