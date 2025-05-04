"""Tests for observability/logging.py"""

import json
import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from observability.logging import JsonFormatter, setup_logging

# --- Fixtures ---


@pytest.fixture
def mock_logging_setup():
    """Fixture to mock the logging setup components."""
    # Create mocks for the logging components
    mock_file_handler = MagicMock()
    mock_console_handler = MagicMock()
    mock_path = MagicMock()

    # Create log dir path object for assertions
    log_dir_path = MagicMock()
    log_dir_path.mkdir = MagicMock()

    # Configure the mock Path instance
    mock_path.return_value = MagicMock()
    mock_path.return_value.parent = log_dir_path

    # Patching
    with patch("observability.logging.Path", mock_path), patch(
        "observability.logging.RotatingFileHandler", return_value=mock_file_handler
    ), patch("logging.StreamHandler", return_value=mock_console_handler), patch(
        "logging.getLogger"
    ) as mock_get_logger:
        # Set up mock logger
        mock_logger = MagicMock()
        mock_logger.hasHandlers.return_value = False
        mock_get_logger.return_value = mock_logger

        yield {
            "logger": mock_logger,
            "file_handler": mock_file_handler,
            "console_handler": mock_console_handler,
            "log_dir": log_dir_path,
        }


@pytest.fixture
def log_record():
    """Creates a basic log record for testing the formatter."""
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="/path/to/test.py",
        lineno=10,
        msg="Test log message with %s",
        args=("extra_data",),
        exc_info=None,
        func="test_function",
    )
    # Add some extra data
    record.extra_field = "extra_value"
    return record


# --- Test Cases ---


def test_setup_logging_defaults(mock_logging_setup):
    """Test setup_logging with default INFO level."""
    mocks = mock_logging_setup
    with patch.dict(os.environ, {}, clear=True):  # Ensure no LOG_LEVEL env var
        setup_logging()

    # Verify directory creation
    mocks["log_dir"].mkdir.assert_called_once_with(parents=True, exist_ok=True)

    # Verify console handler level is set to INFO (20)
    mocks["console_handler"].setLevel.assert_called_with(logging.INFO)

    # Verify file handler level is set to DEBUG (10)
    mocks["file_handler"].setLevel.assert_called_with(logging.DEBUG)

    # Verify handlers were added to logger (4 handlers are added in total)
    assert (
        mocks["logger"].addHandler.call_count >= 2
    )  # At least our mocked console & file handlers


@pytest.mark.parametrize(
    "level_arg, expected_level",
    [
        ("DEBUG", logging.DEBUG),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("INFO", logging.INFO),
        ("INVALID_LEVEL", logging.INFO),  # Test invalid level defaults to INFO
        (None, logging.INFO),  # Test None defaults to INFO (assuming no env var)
    ],
)
def test_setup_logging_with_arg(mock_logging_setup, level_arg, expected_level):
    """Test setup_logging with log_level_arg."""
    mocks = mock_logging_setup
    with patch.dict(os.environ, {}, clear=True):
        setup_logging(log_level_arg=level_arg)

    # Verify console handler level is set correctly
    mocks["console_handler"].setLevel.assert_called_with(expected_level)

    # Verify file handler level is always DEBUG
    mocks["file_handler"].setLevel.assert_called_with(logging.DEBUG)


def test_setup_logging_with_env_var(mock_logging_setup):
    """Test setup_logging respects LOG_LEVEL environment variable."""
    mocks = mock_logging_setup
    with patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}):
        setup_logging()  # No arg passed, should use env var

    # Verify console handler level is set to WARNING (30)
    mocks["console_handler"].setLevel.assert_called_with(logging.WARNING)


def test_setup_logging_arg_overrides_env_var(mock_logging_setup):
    """Test setup_logging log_level_arg overrides LOG_LEVEL environment variable."""
    mocks = mock_logging_setup
    with patch.dict(os.environ, {"LOG_LEVEL": "ERROR"}):
        setup_logging(log_level_arg="DEBUG")  # Arg should take precedence

    # Verify console handler level is set to DEBUG (10) - arg took precedence
    mocks["console_handler"].setLevel.assert_called_with(logging.DEBUG)


def test_json_formatter(log_record):
    """Test the JsonFormatter formats records correctly."""
    formatter = JsonFormatter()
    formatted_string = formatter.format(log_record)
    log_entry = json.loads(formatted_string)

    assert log_entry["level"] == "INFO"
    assert log_entry["logger"] == "test_logger"
    assert log_entry["message"] == "Test log message with extra_data"
    assert log_entry["extra_field"] == "extra_value"
    assert "timestamp" in log_entry
    assert log_entry.get("exception") is None
    assert log_entry.get("stack_info") is None


def test_json_formatter_with_exception(log_record):
    """Test the JsonFormatter includes exception info."""
    formatter = JsonFormatter()
    try:
        raise ValueError("Test exception")
    except ValueError:
        log_record.exc_info = logging.sys.exc_info()

    formatted_string = formatter.format(log_record)
    log_entry = json.loads(formatted_string)

    assert log_entry["level"] == "INFO"
    assert log_entry["message"] == "Test log message with extra_data"
    assert "exception" in log_entry
    assert "ValueError: Test exception" in log_entry["exception"]
