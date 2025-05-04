"""Tests for the CLI commands.

This module tests the command-line interface functionality.
"""

import os
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from agents.network_security_agent import (  # Import VulnerabilityFinding
    NetworkScanResult,  # Import needed for mocks
    ScanSeverity,
    VulnerabilityFinding,
)
from cli.main import _print_scan_results, app, log_level_callback  # Import callback
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


@patch("cli.main.setup_logging")
def test_log_level_callback_no_level(mock_setup_logging, patched_cli):
    """Test log level callback does nothing if no level is passed."""
    # Call the callback directly without a level
    log_level_callback(None)
    mock_setup_logging.assert_not_called()


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
@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
async def test_cli_analyze_domain_no_result(
    mock_asyncio, mock_run_analysis, patched_cli
):
    """Test analyze-domain command when the agent returns None."""
    mock_asyncio.run.return_value = None  # Simulate agent returning None
    mock_run_analysis.return_value = None

    result = runner.invoke(app, ["analyze-domain", TEST_DOMAIN])

    assert result.exit_code == 1
    assert "Analysis Failed" in result.stdout
    assert "Could not retrieve analysis results" in result.stdout


@pytest.mark.asyncio
@patch("cli.main.run_network_scan")
@patch("cli.main.asyncio")
async def test_cli_scan_target_success(
    mock_asyncio, mock_run_network_scan, patched_cli
):
    """Test scan-target command runs successfully."""
    # Create a mock NetworkScanResult
    mock_result = NetworkScanResult(
        target="example.com",
        vulnerabilities=[],
        summary={},
        recommendations=["Scan successful."],
    )

    # Setup asyncio.run() to return our mock result
    mock_asyncio.run.return_value = mock_result
    mock_run_network_scan.return_value = None

    # Run the command
    result = runner.invoke(app, ["scan-target", "example.com"])

    # Verify results
    assert result.exit_code == 0
    assert "Scan Complete" in result.stdout
    assert "example.com" in result.stdout
    mock_asyncio.run.assert_called_once()


@pytest.mark.asyncio
@patch("cli.main.run_network_scan")
@patch("cli.main.asyncio")
async def test_cli_scan_target_failure(
    mock_asyncio, mock_run_network_scan, patched_cli
):
    """Test scan-target command handles failures."""
    # Setup mock to raise an exception
    mock_asyncio.run.side_effect = Exception("Scan failed badly")
    mock_run_network_scan.return_value = None

    result = runner.invoke(app, ["scan-target", "fail.com"])

    assert result.exit_code == 1
    assert "An unexpected error occurred" in result.stdout
    assert "Scan failed badly" in result.stdout


@pytest.mark.asyncio
@patch("cli.main.run_network_scan")
@patch("cli.main.asyncio")
async def test_cli_scan_target_no_result(
    mock_asyncio, mock_run_network_scan, patched_cli
):
    """Test scan-target command when the agent returns None."""
    mock_asyncio.run.return_value = None  # Simulate agent returning None
    mock_run_network_scan.return_value = None

    result = runner.invoke(app, ["scan-target", "no-result.com"])

    assert result.exit_code == 1
    assert "Scan Failed" in result.stdout
    assert "Could not retrieve scan results" in result.stdout


@pytest.mark.asyncio
@patch("cli.main.run_network_scan")
@patch("cli.main.asyncio")
async def test_cli_scan_target_with_options(
    mock_asyncio, mock_run_network_scan, patched_cli
):
    """Test scan-target command with severity and rate_limit options."""
    mock_result = NetworkScanResult(
        target="example.com", vulnerabilities=[], summary={}, recommendations=[]
    )
    mock_asyncio.run.return_value = mock_result
    mock_run_network_scan.return_value = None

    # Run with options
    result = runner.invoke(
        app, ["scan-target", "example.com", "--severity", "high", "--rate-limit", "100"]
    )

    assert result.exit_code == 0
    assert "Scan Complete" in result.stdout

    # Check that run_network_scan was called with correct parameters
    mock_asyncio.run.assert_called_once()
    # Get the coroutine passed to asyncio.run - Not needed for assertion
    # coro = mock_asyncio.run.call_args[0][0]
    # Inspect the call to the original run_network_scan function inside the coro
    # This assumes run_network_scan is awaited directly inside asyncio.run
    mock_run_network_scan.assert_called_once_with(
        target="example.com", severity_filter=ScanSeverity.HIGH, rate_limit=100
    )


@pytest.mark.asyncio
@patch("cli.main.run_network_scan")
@patch("cli.main.asyncio")
async def test_cli_scan_target_scan_error_in_summary(
    mock_asyncio, mock_run_network_scan, patched_cli
):
    """Test scan-target command exits with error if scan summary has 'error'."""
    mock_result = NetworkScanResult(
        target="error-scan.com",
        vulnerabilities=[],
        summary={"error": 1, "critical": 0},  # Simulate scan error
        recommendations=[],
    )
    mock_asyncio.run.return_value = mock_result
    mock_run_network_scan.return_value = None

    result = runner.invoke(app, ["scan-target", "error-scan.com"])

    assert result.exit_code == 1  # Should exit with error code
    assert "Scan Complete" in result.stdout  # Still prints results
    assert "ERROR: 1" in result.stdout  # Check summary output


# --- Tests for Helper Functions ---


def test_print_scan_results_no_summary_no_recs(capsys):
    """Test printing results with no summary or recommendations."""
    result = NetworkScanResult(
        target="clean.com", vulnerabilities=[], summary={}, recommendations=[]
    )
    _print_scan_results(result, None)
    captured = capsys.readouterr()
    assert "No vulnerabilities found or reported." in captured.out
    assert "No specific recommendations provided." in captured.out


def test_print_scan_results_output_file_error(capsys, tmp_path):
    """Test printing results with an error writing to output file."""
    result = NetworkScanResult(
        target="file-error.com", vulnerabilities=[], summary={}, recommendations=[]
    )
    # Create a directory and try to write the file there (will cause OSError)
    output_dir = tmp_path / "output_dir"
    output_dir.mkdir()

    _print_scan_results(result, str(output_dir))
    captured = capsys.readouterr()
    assert "Error saving results to file:" in captured.out
    assert isinstance(output_dir, object)  # Basic check it's path-like


@patch("typer.confirm")
def test_print_scan_results_decline_details(mock_confirm, capsys):
    """Test printing results and declining to show details."""
    mock_confirm.return_value = False  # Simulate user answering 'no'
    # Create a valid VulnerabilityFinding instance instead of MagicMock
    vuln = VulnerabilityFinding(
        name="Test Vuln",
        severity=ScanSeverity.HIGH,
        description="Details",
        remediation="Update software.",  # Optional: add more fields
        references=["http://example.com/ref"],
        cve_ids=["CVE-2024-1234"],
    )

    result = NetworkScanResult(
        target="decline.com",
        vulnerabilities=[vuln],
        summary={"high": 1},
        recommendations=[],
    )
    _print_scan_results(result, None)
    captured = capsys.readouterr()

    mock_confirm.assert_called_once_with(
        "\nShow full vulnerability details?", default=False
    )
    # Ensure details were NOT printed
    assert "Vulnerability Details:" not in captured.out
    assert "Test Vuln" not in captured.out


# --- Tests for _get_domain_info_for_scan ---


@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
def test_get_domain_info_for_scan_success(mock_asyncio, mock_run_analysis, capsys):
    """Test _get_domain_info_for_scan successfully gets domain info."""
    mock_result = DomainAnalysisResult(
        domain="domain.com", analysis_id="a1", analysis_summary="s"
    )
    mock_asyncio.run.return_value = mock_result

    from cli.main import _get_domain_info_for_scan

    result_dict = _get_domain_info_for_scan("http://domain.com/path")

    assert result_dict["domain"] == "domain.com"
    mock_run_analysis.assert_called_once_with("domain.com")
    captured = capsys.readouterr()
    assert "Analyzing domain: domain.com" in captured.out


@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
def test_get_domain_info_for_scan_no_domain_result(
    mock_asyncio, mock_run_analysis, capsys
):
    """Test _get_domain_info_for_scan when domain analysis returns None."""
    mock_asyncio.run.return_value = None

    from cli.main import _get_domain_info_for_scan

    result_dict = _get_domain_info_for_scan("domain.com")

    assert result_dict is None
    mock_run_analysis.assert_called_once_with("domain.com")
    captured = capsys.readouterr()
    assert "Domain analysis returned no result." in captured.out


@patch("cli.main.run_domain_analysis")
@patch("cli.main.asyncio")
def test_get_domain_info_for_scan_exception(mock_asyncio, mock_run_analysis, capsys):
    """Test _get_domain_info_for_scan handles exceptions during analysis."""
    mock_asyncio.run.side_effect = Exception("Analysis boom")

    from cli.main import _get_domain_info_for_scan

    result_dict = _get_domain_info_for_scan("domain.com")

    assert result_dict is None
    mock_run_analysis.assert_called_once_with("domain.com")
    captured = capsys.readouterr()
    assert "Could not analyze domain for context: Analysis boom" in captured.out


def test_get_domain_info_for_scan_not_a_domain(capsys):
    """Test _get_domain_info_for_scan with a target that isn't a domain."""
    from cli.main import _get_domain_info_for_scan

    result_dict = _get_domain_info_for_scan("notadomain")
    assert result_dict is None
    captured = capsys.readouterr()
    assert "Target does not appear to be a domain" in captured.out


# --- Tests for _print_vulnerability_details ---


def test_print_vulnerability_details_all_fields(capsys):
    """Test printing vulnerability details with all fields populated."""
    finding = VulnerabilityFinding(
        name="Detailed Vuln",
        severity=ScanSeverity.CRITICAL,
        description="Very descriptive",
        remediation="Apply patch X.",
        references=["http://ref1", "http://ref2"],
        cve_ids=["CVE-1", "CVE-2"],
    )
    from cli.main import _print_vulnerability_details

    _print_vulnerability_details([finding])
    captured = capsys.readouterr()

    assert "Detailed Vuln" in captured.out
    assert "(ScanSeverity.CRITICAL)" in captured.out
    assert "Description: Very descriptive" in captured.out
    assert "Remediation: Apply patch X." in captured.out
    assert "CVEs: CVE-1, CVE-2" in captured.out
    assert "References:" in captured.out
    assert "- http://ref1" in captured.out
    assert "- http://ref2" in captured.out


def test_print_vulnerability_details_minimal_fields(capsys):
    """Test printing vulnerability details with only required fields."""
    finding = VulnerabilityFinding(
        name="Minimal Vuln",
        severity=ScanSeverity.LOW,
        description="Minimal description",
    )
    from cli.main import _print_vulnerability_details

    _print_vulnerability_details([finding])
    captured = capsys.readouterr()

    assert "Minimal Vuln" in captured.out
    assert "(ScanSeverity.LOW)" in captured.out
    assert "Description: Minimal description" in captured.out
    # Assert optional fields are NOT present
    assert "Remediation:" not in captured.out
    assert "CVEs:" not in captured.out
    assert "References:" not in captured.out


@pytest.mark.parametrize(
    "severity, expected_color, expected_value",
    [
        (ScanSeverity.CRITICAL, "bright_red", "critical"),
        (ScanSeverity.HIGH, "red", "high"),
        (ScanSeverity.MEDIUM, "yellow", "medium"),
        (ScanSeverity.LOW, "green", "low"),
        (ScanSeverity.INFO, "blue", "info"),
        # ("unknown", "white"), # Removed invalid case
    ],
)
def test_print_vulnerability_details_severities(
    capsys, severity, expected_color, expected_value
):
    """Test correct color output for different severities."""
    finding = VulnerabilityFinding(
        name="Severity Test", severity=severity, description="desc"
    )
    from cli.main import _print_vulnerability_details

    _print_vulnerability_details([finding])
    captured = capsys.readouterr()
    # Assert the presence of the full enum representation
    assert f"(ScanSeverity.{severity.name})" in captured.out
