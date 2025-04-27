"""Logging configuration for structured JSON logging."""

import json
import logging
import logging.config
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON strings."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            # Include exception info if present
            "exception": (
                self.formatException(record.exc_info) if record.exc_info else None
            ),
            # Include stack info if present (e.g., from logger.stack())
            "stack_info": (
                self.formatStack(record.stack_info) if record.stack_info else None
            ),
        }
        # Add any extra fields passed to the logger
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in log_entry and key not in (
                    "args",
                    "asctime",
                    "created",
                    "exc_info",
                    "exc_text",
                    "filename",
                    "funcName",
                    "levelname",
                    "levelno",
                    "lineno",
                    "message",
                    "module",
                    "msecs",
                    "msg",
                    "name",
                    "pathname",
                    "process",
                    "processName",
                    "relativeCreated",
                    "stack_info",
                    "thread",
                    "threadName",
                ):
                    log_entry[key] = value

        # Ensure all values are serializable
        # A simple approach: convert non-serializable items to string
        serializable_entry = {
            k: (
                str(v)
                if not isinstance(v, (str, int, float, bool, list, dict, tuple))
                else v
            )
            for k, v in log_entry.items()
            if v is not None
        }

        return json.dumps(serializable_entry)


def setup_logging(log_level: str = "INFO"):
    """Configure root logger for JSON output to stdout.

    Args:
        log_level: The minimum log level (e.g., "DEBUG", "INFO", "WARNING").
    """
    # --- Define Log File Path --- #
    log_file_path = "logs/app.log"
    log_file_path_obj = Path(log_file_path)

    log_dir_obj = log_file_path_obj.parent
    log_dir_obj.mkdir(parents=True, exist_ok=True)

    # --- Determine Log Level --- #
    log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_levels = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }
    log_level = log_levels.get(
        log_level_str, logging.INFO
    )  # Default to INFO if invalid

    # --- Root Logger Configuration --- #
    # Configure the root logger - this applies to all loggers unless overridden
    # Set the root logger level first
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers (important if this function is called multiple times)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # --- Formatter --- #
    # Consistent JSON formatter
    formatter = logging.Formatter(
        fmt='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        datefmt="%Y-%m-%d %H:%M:%S,%f"[:-3],
    )

    # --- Handlers --- #
    # 1. Console Handler (uses the resolved log_level)
    console_handler = logging.StreamHandler(sys.stdout)  # Explicitly use stdout
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    # 2. Rotating File Handler (DEBUG level)
    file_handler = RotatingFileHandler(
        log_file_path_obj, maxBytes=10 * 1024 * 1024, backupCount=5  # 10 MB
    )
    file_handler.setLevel(logging.DEBUG)  # Always capture DEBUG in file
    file_handler.setFormatter(formatter)

    # --- Add Handlers to Root Logger --- #
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Log confirmation *after* handlers are added
    root_logger.info(
        f"Logging setup complete. Console Level: {log_level_str}, File Level: DEBUG"
    )

    # --- Optional: Logfire Integration --- #
    # If Logfire integration is enabled via environment variable or config
    logfire_enabled = os.getenv("LOGFIRE_ENABLED", "false").lower() == "true"
    logfire_token = os.getenv("LOGFIRE_TOKEN")  # Or other config mechanism

    if logfire_enabled:
        if logfire_token:
            try:
                # Ensure Logfire is imported only if enabled
                import logfire

                # Configure Logfire
                logfire.configure(send_to_logfire=True, token=logfire_token)
                # Instrument libraries (consider moving instrumentation to app startup)
                logfire.instrument_httpx()
                logfire.instrument_openai()  # If using OpenAI
                # Add other instrumentations as needed (e.g., Bedrock)

                root_logger.info("Logfire integration enabled and configured.")

                # Optional: Add Logfire handler to root logger
                # Note: Logfire typically captures logs automatically via instrumentation
                # You might not need an explicit handler unless you want fine control
                # logfire_handler = logfire.LogfireHandler()
                # root_logger.addHandler(logfire_handler)

            except ImportError:
                root_logger.warning(
                    "Logfire enabled but 'logfire' package not found. Skipping."
                )
            except Exception as e:
                root_logger.error(f"Failed to configure Logfire: {e}")
        else:
            root_logger.warning(
                "Logfire enabled but LOGFIRE_TOKEN environment variable not set."
            )

    # Adjust log levels for noisy libraries if needed
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    root_logger.info(f"Logging setup complete. Level: {log_level}")
