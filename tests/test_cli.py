"""Tests for the CLI commands.

This module tests the command-line interface functionality.
"""

import os
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from cli.main import app
from schemas.domain_analysis import DomainAnalysisResult

TEST_DOMAIN = "example-cli.com"
TEST_LOG_FILE = "test_cli_log.log"

# Create runner instance at module level
runner = CliRunner()


# --- Test Fixtures --- #


@pytest.fixture
def mock_initialize_system():
    """Mock the initialization function to avoid side effects."""
    with patch("cli.main.initialize_system") as mock_init:
        yield mock_init


@pytest.fixture
def patched_cli(mock_initialize_system):
    """Provide common fixtures for CLI tests."""
    return {"app": app, "mock_initialize_system": mock_initialize_system}


# --- Helper Functions --- #


def read_test_log(log_path):
    """Read test log file contents."""
    if os.path.exists(log_path):
        with open(log_path) as f:
            return f.read()
        os.unlink(log_path)  # Clean up
    return ""


# --- Test Cases --- #


def test_info_command(patched_cli):
    """Test the 'info' command works correctly."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "SuperCyberAgents CLI Information" in result.stdout


def test_non_existent_command(patched_cli):
    """Test behavior with a command that doesn't exist."""
    result = runner.invoke(app, ["nonexistentcommand"])
    assert result.exit_code != 0  # Should fail


def test_help_command(patched_cli):
    """Test the help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "SuperCyberAgents CLI" in result.stdout


@patch("cli.main.setup_logging")
def test_log_level_callback(mock_setup_logging, patched_cli):
    """Test log level callback functionality."""
    result = runner.invoke(app, ["--log-level", "DEBUG", "info"])
    assert result.exit_code == 0
    # Should be called with DEBUG log level
    mock_setup_logging.assert_called_with(log_level_arg="DEBUG")


# --- Modified CLI Command Tests --- #


@pytest.mark.asyncio
@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
async def test_cli_analyze_domain_success(
    mock_asyncio, mock_run_analysis, patched_cli, capsys
):
    """Test analyze-domain command runs successfully."""
    # Create mock result
    mock_result = DomainAnalysisResult(
        domain=TEST_DOMAIN, analysis_id="test123", analysis_summary="Success!"
    )

    # Setup asyncio.run() to return our mock result
    mock_asyncio.run.return_value = mock_result
    mock_run_analysis.return_value = None  # Not used directly

    # Run the command
    result = runner.invoke(app, ["analyze-domain", TEST_DOMAIN])

    # Verify results
    assert result.exit_code == 0
    assert "Analysis Complete" in result.stdout
    assert TEST_DOMAIN in result.stdout


@pytest.mark.asyncio
@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
async def test_cli_analyze_domain_failure(mock_asyncio, mock_run_analysis, patched_cli):
    """Test analyze-domain command handles failures."""
    # Setup mock to raise an exception
    mock_asyncio.run.side_effect = Exception("Test failure")
    mock_run_analysis.return_value = None  # Not used directly

    # Run the command
    result = runner.invoke(app, ["analyze-domain", TEST_DOMAIN])

    # Verify results
    assert result.exit_code == 1
    assert "An unexpected error occurred" in result.stdout


@pytest.mark.asyncio
@patch("cli.main.network_security_agent.scan_target")
@patch("cli.main.asyncio")
async def test_cli_scan_target_success(mock_asyncio, mock_scan_target, patched_cli):
    """Test scan-target command runs successfully."""
    # Import here to avoid circular imports
    from agents.network_security_agent import NetworkScanResult

    # Create a mock NetworkScanResult
    mock_result = NetworkScanResult(
        target="example.com",
        summary={"critical": 1, "high": 2, "medium": 3},
        recommendations=["Fix critical issue"],
    )

    # Setup asyncio.run() to return our mock result
    mock_asyncio.run.return_value = mock_result
    mock_scan_target.return_value = None  # Not used directly

    # Run the command
    result = runner.invoke(app, ["scan-target", "example.com", "--severity", "high"])

    # Verify results
    assert result.exit_code == 0
    assert "Scan Complete" in result.stdout
    assert "example.com" in result.stdout
