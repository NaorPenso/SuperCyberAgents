"""Command Line Interface using Typer."""

import asyncio  # Import asyncio for async command
import json
import logging
from enum import Enum
from typing import Optional

import typer
from dotenv import load_dotenv  # Import dotenv
from rich import print as rprint

# Import specific agent functions/schemas when adding commands
from agents.domain_analyzer_agent import run_domain_analysis
from agents.network_security_agent import ScanSeverity, network_security_agent

# --- Project Imports --- #
from core.initialization import initialize_system  # Keep initialization
from observability.logging import setup_logging

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


# Helper function to handle async agent operations
def run_async(coroutine):
    """Run a coroutine and return its result."""
    return asyncio.run(coroutine)


@app.command()
def info():
    """Display information about the system."""
    rprint(":information_source: [bold]SuperCyberAgents CLI Information[/bold]")
    rprint("A command-line interface for interacting with Pydantic-AI agents.")
    rprint("\nUse [bold]--help[/bold] for available commands and options.")
    return 0  # Ensure successful exit code


@app.command()
def analyze_domain(
    domain: str = typer.Argument(..., help="The domain name to analyze.")
):
    """Run the Domain Analyzer agent for a specific domain."""
    rprint(f":mag: Running Domain Analysis for: [bold blue]{domain}[/bold blue]")

    try:
        # Use asyncio.run to execute the async domain analysis function
        result = run_async(run_domain_analysis(domain))

        if result:
            rprint("\n:white_check_mark: [bold green]Analysis Complete:[/bold green]")
            rprint(result.model_dump_json(indent=2))
        else:
            rprint("\n:x: [bold red]Analysis Failed.[/bold red]")
            rprint("Could not retrieve analysis results. Check logs for details.")
            raise typer.Exit(code=1)
    except Exception as e:
        logger.exception(f"Unexpected error during domain analysis: {e}")
        rprint(f"\n:x: [bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1) from e


@app.command()
def scan_target(
    target: str = typer.Argument(..., help="Target URL, domain, or IP to scan"),
    severity: Optional[ScanSeverity] = typer.Option(
        None,
        "--severity",
        "-s",
        case_sensitive=False,
        help="Only include vulnerabilities of this severity and higher",
    ),
    rate_limit: int = typer.Option(
        150, "--rate-limit", "-r", help="Maximum requests per minute", min=10, max=1000
    ),
    use_domain_info: bool = typer.Option(
        False,
        "--use-domain-info",
        "-d",
        help="Use results from domain analysis if available",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file"
    ),
):
    """Run a security scan on a target using the NetworkSecurityAgent."""
    rprint(f":shield: Running Security Scan for: [bold blue]{target}[/bold blue]")
    if severity:
        rprint(f"Severity filter: [bold yellow]{severity}[/bold yellow] and higher")
    if use_domain_info:
        rprint("Including domain analysis information in scan context")

    try:
        # Extract domain information if requested
        domain_info = None
        if use_domain_info:
            try:
                from urllib.parse import urlparse

                # Extract domain from target
                parsed = urlparse(target if "//" in target else f"http://{target}")
                domain = parsed.netloc or parsed.path
                domain = domain.split(":")[0]  # Remove port if present

                if "." in domain:
                    rprint(
                        f"Analyzing domain: [italic]{domain}[/italic] for additional context..."
                    )
                    domain_result = run_async(run_domain_analysis(domain))
                    if domain_result:
                        domain_info = domain_result.model_dump(
                            exclude={"analysis_id", "timestamp"}
                        )
                        rprint(":white_check_mark: Domain analysis complete")
            except Exception as e:
                rprint(f":warning: Could not analyze domain: {e}")
                rprint("Continuing scan without domain information")

        # Run the security scan
        rprint("Starting security scan... (this may take a while)")
        result = run_async(
            network_security_agent.scan_target(
                target=target,
                domain_info=domain_info,
                severity_filter=severity,
                rate_limit=rate_limit,
            )
        )

        if result:
            rprint("\n:white_check_mark: [bold green]Scan Complete:[/bold green]")

            # Display vulnerability counts by severity
            rprint("\n[bold]Vulnerability Summary:[/bold]")
            if result.summary:
                for severity_level, count in result.summary.items():
                    severity_color = {
                        "critical": "bright_red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "green",
                        "info": "blue",
                        "error": "red",
                    }.get(severity_level.lower(), "white")

                    rprint(
                        f"  [{severity_color}]{severity_level.upper()}[/{severity_color}]: {count}"
                    )
            else:
                rprint("  No vulnerabilities found")

            # Display recommendations
            if result.recommendations:
                rprint("\n[bold]Recommendations:[/bold]")
                for i, rec in enumerate(result.recommendations, 1):
                    rprint(f"  {i}. {rec}")

            # Save to file if requested
            if output_file:
                with open(output_file, "w") as f:
                    json.dump(
                        result.model_dump(),
                        f,
                        indent=2,
                        default=str,  # Handle datetime serialization
                    )
                rprint(f"\nResults saved to: [bold blue]{output_file}[/bold blue]")

            # Ask if user wants to see full details
            if result.vulnerabilities and not typer.confirm(
                "\nShow full vulnerability details?", default=False
            ):
                return 0

            # Show full vulnerability details if confirmed
            if result.vulnerabilities:
                rprint("\n[bold]Vulnerability Details:[/bold]")
                for i, vuln in enumerate(result.vulnerabilities, 1):
                    severity_color = {
                        ScanSeverity.CRITICAL: "bright_red",
                        ScanSeverity.HIGH: "red",
                        ScanSeverity.MEDIUM: "yellow",
                        ScanSeverity.LOW: "green",
                        ScanSeverity.INFO: "blue",
                    }.get(vuln.severity, "white")

                    rprint(
                        f"\n{i}. [bold]{vuln.name}[/bold] ([{severity_color}]{vuln.severity}[/{severity_color}])"
                    )
                    rprint(f"   Description: {vuln.description}")

                    if vuln.remediation:
                        rprint(f"   Remediation: {vuln.remediation}")

                    if vuln.cve_ids:
                        rprint(f"   CVEs: {', '.join(vuln.cve_ids)}")

                    if vuln.references:
                        rprint("   References:")
                        for ref in vuln.references:
                            rprint(f"     - {ref}")

            return 0
        else:
            rprint("\n:x: [bold red]Scan Failed.[/bold red]")
            rprint("Could not retrieve scan results. Check logs for details.")
            raise typer.Exit(code=1)
    except Exception as e:
        logger.exception(f"Unexpected error during security scan: {e}")
        rprint(f"\n:x: [bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1) from e


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


# --- How to Run --- #
# This CLI is intended to be run using the `typer` command runner
# or via a configured script entry point in pyproject.toml.
# Example using typer runner:
# poetry run typer cli/main.py run analyze-domain example.com
#
# Example using script entry point (if configured as 'cyberagents'):
# poetry run cyberagents analyze-domain example.com
#
# Direct execution (`python cli/main.py ...`) is not recommended for
# applications with async commands as it may not handle the event loop correctly.

# Add entry point for direct execution
if __name__ == "__main__":
    app()
