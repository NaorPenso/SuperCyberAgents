"""Command Line Interface using Typer."""

import logging
from enum import Enum
from typing import Optional

import typer
from dotenv import load_dotenv  # Import dotenv
from rich import print as rprint

# --- Project Imports --- #
from core.initialization import initialize_system  # Keep initialization
from observability.logging import setup_logging

# Import specific agent functions/schemas when adding commands
# Example: from agents.log_analyzer_agent import analyze_log_entry, ExampleAgentInput

# Load environment variables from .env file early
load_dotenv()


# Define LogLevel enum for Typer Choice
class LogLevel(str, Enum):
    debug = "DEBUG"
    info = "INFO"
    warning = "WARNING"
    error = "ERROR"
    critical = "CRITICAL"


# Initialize logging (will be reconfigured by callback if log level is passed)
setup_logging()

logger = logging.getLogger(__name__)  # Define logger at module level


# --- Callback for Log Level --- #
def log_level_callback(level: LogLevel | None):
    if level:
        logger.info(f"Setting log level to: {level.value}")
        setup_logging(log_level_arg=level.value)


# --- CLI App Setup ---
app = typer.Typer(
    help="SuperCyberAgents CLI - Interact with Pydantic-AI agents.",
    add_completion=False,
)

# We can add sub-apps later if needed, e.g., for specific agent types
# agents_app = typer.Typer(help="Run specific agents.")
# app.add_typer(agents_app, name="agent")

# --- Initialization ---
# Run initialization eagerly when CLI module is loaded
try:
    initialize_system()  # Now only initializes providers
except Exception as e:
    rprint(f":x: [bold red]System initialization failed:[/bold red] {e}")
    rprint("CLI might not function correctly.")


# --- Removed Old Helper Functions --- #
# _get_schema_class_cli, _load_cli_input, _validate_cli_agent_input removed

# --- Removed Old Agent Commands --- #
# `agent list` and `agent run` commands removed

# --- Placeholder for New Commands --- #


# --- Commands --- #

# Removed `analyze-log` command

# TODO: Add commands for agents as they are implemented.


@app.command()
def info():
    """Display information about the system."""
    rprint(":information_source: [bold]SuperCyberAgents CLI Information[/bold]")
    rprint("A command-line interface for interacting with Pydantic-AI agents.")
    rprint("\nUse [bold]--help[/bold] for available commands and options.")
    return 0  # Ensure successful exit code


# --- Main Callback (Optional) ---
@app.callback()
def main_callback(
    ctx: typer.Context,
    log_level: Optional[LogLevel] = typer.Option(  # noqa: B008
        None,
        "--log-level",
        "-L",
        help="Set logging level.",
    ),
):
    """
    SuperCyberAgents CLI
    """
    log_level_callback(log_level)
    pass


# --- Run Dunder Check (Optional) ---
# if __name__ == "__main__":
#    app() # Allows running the CLI script directly
