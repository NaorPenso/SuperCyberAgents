"""Command Line Interface using Typer."""

import asyncio  # Import asyncio for async command
import json
import logging
from enum import Enum
from typing import Any, Dict, Optional

import typer
from dotenv import load_dotenv  # Import dotenv
from rich import print as rprint
from rich.console import Console  # Import Console

# Import specific agent functions/schemas when adding commands
from agents.domain_analyzer_agent import DomainAnalysisResult, run_domain_analysis
from agents.network_security_agent import NetworkScanResult, ScanSeverity
from agents.network_security_agent import (
    scan_target as run_network_scan,  # Rename to avoid conflict
)

# --- Project Imports --- #
from core.initialization import initialize_system  # Keep initialization
from observability.logging import setup_logging

# Load environment variables from .env file early
load_dotenv()

# Create a global console instance for status spinners etc.
console = Console()


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
    domain: str = typer.Argument(..., help="The domain name to analyze."),
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


# --- scan-target Helper Functions ---


def _get_domain_info_for_scan(target: str) -> Optional[Dict[str, Any]]:
    """Attempt to get domain analysis info for a scan target."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(target if "//" in target else f"http://{target}")
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]  # Remove port

        if "." in domain:
            rprint(f"Analyzing domain: [italic]{domain}[/italic] for context...")
            domain_result: Optional[DomainAnalysisResult] = run_async(
                run_domain_analysis(domain)
            )
            if domain_result:
                rprint(":white_check_mark: Domain analysis complete")
                return domain_result.model_dump(exclude={"analysis_id", "timestamp"})
            else:
                rprint(":warning: Domain analysis returned no result.")
        else:
            rprint(
                ":information_source: Target does not appear to be a domain, "
                "skipping analysis."
            )
    except Exception as e:
        rprint(f":warning: Could not analyze domain for context: {e}")
        rprint("Continuing scan without domain information.")
    return None


def _print_vulnerability_details(vulnerabilities: list[Any]):
    """Print detailed information for a list of vulnerabilities."""
    rprint("\n[bold]Vulnerability Details:[/bold]")
    for i, vuln in enumerate(vulnerabilities, 1):
        severity_color = {
            ScanSeverity.CRITICAL: "bright_red",
            ScanSeverity.HIGH: "red",
            ScanSeverity.MEDIUM: "yellow",
            ScanSeverity.LOW: "green",
            ScanSeverity.INFO: "blue",
        }.get(vuln.severity, "white")

        rprint(  # Wrapped long f-string
            f"\n{i}. [bold]{vuln.name}[/bold] "
            f"([{severity_color}]{vuln.severity}[/{severity_color}])"
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


def _print_scan_results(result: NetworkScanResult, output_file: Optional[str]):
    """Print the results of a network scan in a user-friendly format."""
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
                f"  [{severity_color}]{severity_level.upper()}[/{severity_color}]: "
                f"{count}"
            )
    else:
        rprint("  No vulnerabilities found or reported.")  # Clarified message

    # Display recommendations
    if result.recommendations:
        rprint("\n[bold]Recommendations:[/bold]")
        for i, rec in enumerate(result.recommendations, 1):
            rprint(f"  {i}. {rec}")
    else:  # Added else case
        rprint("  No specific recommendations provided.")

    # Save to file if requested
    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(
                    result.model_dump(), f, indent=2, default=str
                )  # Handle datetime
            rprint(f"\nResults saved to: [bold blue]{output_file}[/bold blue]")
        except OSError as e:
            rprint(f":x: [bold red]Error saving results to file:[/bold red] {e}")

    # Ask if user wants to see full details only if vulnerabilities exist
    if result.vulnerabilities and typer.confirm(
        "\nShow full vulnerability details?", default=False
    ):
        _print_vulnerability_details(result.vulnerabilities)


# --- scan-target Command ---


@app.command()
def scan_target(
    target: str = typer.Argument(..., help="The target to scan (domain, IP, or URL)"),
    use_domain_info: bool = typer.Option(
        False, "--use-domain-info", "-d", help="Fetch domain info for context before scanning."
    ),
    severity: Optional[ScanSeverity] = typer.Option(  # noqa: B008
        None, help="Filter results by minimum severity (e.g., high, critical)"
    ),
    rate_limit: Optional[int] = typer.Option(
        None, help="Override default Nuclei rate limit (requests per second)"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save detailed JSON results to a file."
    ),
    # Add other relevant CLI options for NucleiScanParams if desired
):
    """Runs a network security scan using the NetworkSecurityAgent."""
    rprint(f"🛡 Running Security Scan for: {target}")

    domain_info = None
    if use_domain_info:
        domain_info = _get_domain_info_for_scan(target)

    # Prepare parameters for the standalone function
    scan_params = {
        "target": target,
        "domain_info": domain_info,
        "severity_filter": severity,
    }
    if rate_limit is not None:
        scan_params["rate_limit"] = rate_limit

    try:
        # Call the renamed async function
        result: Optional[NetworkScanResult] = run_async(
            run_network_scan(**scan_params)
        )

        if result:
            _print_scan_results(result, output_file)
            # Check if scan itself reported an error in summary
            if result.summary and "error" in result.summary:
                 rprint(
                    ":warning: [bold yellow]Scan completed but reported internal errors.[/bold yellow]"
                 )
                 raise typer.Exit(code=1) # Exit with error code
        else:
            rprint("\n:x: [bold red]Scan Failed.[/bold red]")
            rprint("Could not retrieve scan results. Check logs for details.")
            raise typer.Exit(code=1)

    except Exception as e:
        logger.exception(f"Unexpected error during network scan: {e}")
        rprint(f"\n:x: [bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1) from e


# --- Main Callback (Optional) ---
@app.callback()
def main_callback(
    ctx: typer.Context,
    log_level: Optional[
        LogLevel
    ] = typer.Option(  # noqa: B008 (keep for now, typer limitation)
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
