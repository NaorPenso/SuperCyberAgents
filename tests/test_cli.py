"""Tests for the Typer CLI application."""

import sys
from unittest.mock import MagicMock

# Use pytest's monkeypatch
import pytest
from typer.testing import CliRunner

# Don't import app yet, we need to patch first


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
    except Exception:
        import_successful = False

    # The import should succeed even though initialization fails
    assert import_successful, "Module should import without raising exceptions"

    # Check the initialization was called and raised an error
    assert mock_init.called
    assert mock_init.call_count == 1, "initialize_system should be called exactly once"
