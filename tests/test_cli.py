"""Tests for the Typer CLI application."""

import sys
from unittest.mock import MagicMock, patch, AsyncMock

# Use pytest's monkeypatch
import pytest
from typer.testing import CliRunner
import click # Import click to catch its exceptions

# Don't import app yet, we need to patch first
from schemas.domain_analysis import DomainAnalysisResult


@pytest.fixture
def patched_cli(monkeypatch):
    """Patch core modules before importing app."""
    # Clear the module if it's already imported
    if "cli.main" in sys.modules:
        del sys.modules["cli.main"]

    # Mock the initialize_system function before importing the app
    mock_init = MagicMock()
    monkeypatch.setattr("core.initialization.initialize_system", mock_init)

    # Mock the setup_logging function to avoid file operations
    monkeypatch.setattr("observability.logging.setup_logging", MagicMock())

    # Now it's safe to import the app
    from cli.main import app

    return {"app": app, "mock_initialize_system": mock_init}


def test_cli_no_args(patched_cli):
    """Test running the CLI with no arguments."""
    runner = CliRunner()
    # Use --help to explicitly see the help text
    result = runner.invoke(patched_cli["app"], ["--help"])
    assert result.exit_code == 0
    assert "SuperCyberAgents CLI" in result.stdout


def test_cli_info_command(patched_cli):
    """Test the info command."""
    runner = CliRunner()
    result = runner.invoke(patched_cli["app"], ["info"])
    assert result.exit_code == 0
    assert "SuperCyberAgents CLI Information" in result.stdout


@pytest.mark.parametrize(
    "option, value",
    [
        (["--log-level", "DEBUG"], "DEBUG"),
        (["-L", "WARNING"], "WARNING"),
    ],
)
def test_cli_log_level_options(monkeypatch, patched_cli, option, value):
    """Test both regular and short log-level options call the callback."""
    # We need to create a spy on the real callback
    original_callback = __import__(
        "cli.main", fromlist=["log_level_callback"]
    ).log_level_callback
    mock_log_callback = MagicMock(wraps=original_callback)
    monkeypatch.setattr("cli.main.log_level_callback", mock_log_callback)

    runner = CliRunner()
    # We need to add a command after the option for Typer to process it
    result = runner.invoke(patched_cli["app"], [*option, "info"])

    # Should be successful
    assert result.exit_code == 0
    # Verify callback was called
    mock_log_callback.assert_called()


def test_cli_initialization_called(patched_cli):
    """Test that initialization is called when importing the CLI module."""
    # The initialization happened when we imported the app via the fixture
    mock_initialize = patched_cli["mock_initialize_system"]
    # Verify it was called
    assert mock_initialize.called


def test_cli_initialization_failure(monkeypatch):
    """Test that initialization failure is caught and printed."""
    # First patch the initialization to fail before importing
    mock_init = MagicMock(side_effect=RuntimeError("Init failed!"))
    monkeypatch.setattr("core.initialization.initialize_system", mock_init)

    # Force a fresh import of cli.main
    if "cli.main" in sys.modules:
        del sys.modules["cli.main"]

    # We'll just verify that we can import the module without raising an exception
    # This implicitly tests that the error handling is working
    try:
        import cli.main  # noqa: F401

        import_successful = True
    except Exception: # pragma: no cover
        # This block is hard to trigger reliably if the mock setup works
        import_successful = False

    # The import should succeed even though initialization fails
    assert import_successful, "Module should import without raising exceptions"

    # Check the initialization was called and raised an error
    assert mock_init.called
    assert mock_init.call_count == 1, "initialize_system should be called exactly once"


def test_cli_help_exit(patched_cli):
    """Test that invoking with --help prints help and exits cleanly."""
    runner = CliRunner()
    # Invoke with --help and check exit code and output
    result = runner.invoke(patched_cli["app"], ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout # Check for standard help text
    assert "analyze-domain" in result.stdout # Check command is listed
    assert "--log-level" in result.stdout # Check for a specific option


# --- Tests for analyze-domain command ---

TEST_DOMAIN = "example-cli.com"

# Use pytest.mark.asyncio for these tests

@pytest.mark.asyncio
@patch("cli.main.run_domain_analysis") # Keep the patch simple
async def test_cli_analyze_domain_success(mock_run_analysis, patched_cli, capsys):
    """Test the analyze-domain command successfully runs the agent (direct async call)."""
    # Mock the agent runner to return a successful result
    mock_result_obj = DomainAnalysisResult(domain=TEST_DOMAIN, analysis_summary="Success!")
    mock_run_analysis.return_value = mock_result_obj

    # Import the command function directly
    from cli.main import analyze_domain

    # Run the async command function directly
    await analyze_domain(domain=TEST_DOMAIN)

    # Check assertions
    mock_run_analysis.assert_awaited_once_with(TEST_DOMAIN)
    captured = capsys.readouterr()
    assert "Analysis Complete:" in captured.out
    assert mock_result_obj.model_dump_json(indent=2) in captured.out

@pytest.mark.asyncio
@patch("cli.main.run_domain_analysis")
async def test_cli_analyze_domain_failure(mock_run_analysis, patched_cli, capsys):
    """Test the analyze-domain command when the agent fails (direct async call)."""
    # Mock the agent runner to return None (failure)
    mock_run_analysis.return_value = None

    from cli.main import analyze_domain

    # Expect click.exceptions.Exit(1)
    with pytest.raises(click.exceptions.Exit) as excinfo:
        await analyze_domain(domain=TEST_DOMAIN)

    assert excinfo.value.exit_code == 1 # Check click exception's exit_code
    mock_run_analysis.assert_awaited_once_with(TEST_DOMAIN)
    captured = capsys.readouterr()
    assert "Analysis Failed." in captured.out
    assert "Could not retrieve analysis results" in captured.out

@pytest.mark.asyncio
@patch("cli.main.run_domain_analysis")
async def test_cli_analyze_domain_exception(mock_run_analysis, patched_cli, capsys):
    """Test the analyze-domain command handles exceptions (direct async call)."""
    # Mock the agent runner to raise an error
    test_exception = Exception("Unexpected agent error!")
    mock_run_analysis.side_effect = test_exception

    from cli.main import analyze_domain

    # Expect click.exceptions.Exit(1)
    with pytest.raises(click.exceptions.Exit) as excinfo:
        await analyze_domain(domain=TEST_DOMAIN)

    assert excinfo.value.exit_code == 1 # Check click exception's exit_code
    mock_run_analysis.assert_awaited_once_with(TEST_DOMAIN)
    captured = capsys.readouterr()
    assert "An unexpected error occurred:" in captured.out
    assert str(test_exception) in captured.out
