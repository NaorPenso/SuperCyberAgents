"""Command Line Interface using Typer."""

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from dotenv import load_dotenv  # Import dotenv
from pydantic import BaseModel, ValidationError  # Import directly
from rich import print as rprint

from agents.base import BaseAgent
from core.initialization import get_agent, get_all_agents, initialize_system
# Moved imports to the top
from observability.logging import setup_logging
from schemas.registry import SCHEMA_REGISTRY  # Import the registry

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
    help="Cybersecurity AI Agent CLI - Interact with agents and tools.",
    add_completion=False,
)
agents_app = typer.Typer(help="Manage and run agents.")
app.add_typer(agents_app, name="agent")

# (Add tool_app later if needed)

# --- Initialization ---
# Run initialization eagerly when CLI module is loaded

try:
    initialize_system()
except Exception as e:
    rprint(f":x: [bold red]System initialization failed:[/bold red] {e}")
    rprint("CLI might not function correctly.")

# --- Remove Dynamic Schema Module Loading Section --- #
# schema_modules = []
# schemas_dir = Path(__file__).parent.parent / "schemas"
# try:
#     # Import base schema modules first if they exist
#     if (schemas_dir / "agent_schemas.py").exists():
#         import schemas.agent_schemas
#
#         schema_modules.append(schemas.agent_schemas)
#     if (schemas_dir / "tool_schemas.py").exists():
#         import schemas.tool_schemas
#
#         schema_modules.append(schemas.tool_schemas)
#
#     # Import other schema files dynamically
#     for f in schemas_dir.glob("*_schemas.py"):
#         if f.name not in ["agent_schemas.py", "tool_schemas.py", "__init__.py"]:
#             module_name = f"schemas.{f.stem}"
#             try:
#                 module = importlib.import_module(module_name)
#                 schema_modules.append(module)
#                 logging.debug(f"Dynamically loaded schema module: {module_name}")
#             except ImportError as ie:
#                 logging.warning(f"Could not import schema module {module_name}: {ie}")
# except Exception as e:
#     logging.error(f"Error loading schema modules: {e}")


# --- Helper Functions ---
def _get_schema_class_cli(schema_name: str) -> type[BaseModel] | None:
    """Find a Pydantic schema class by its name using the registry."""
    # for module in schema_modules: # Removed loop
    #     if hasattr(module, schema_name):
    #         cls = getattr(module, schema_name)
    #         if isinstance(cls, type) and issubclass(cls, BaseModel):
    #             return cls
    # return None
    return SCHEMA_REGISTRY.get(schema_name)


def _load_cli_input(
    prompt: str | None,
    input_file: Path | None,
    input_json: str | None,
    agent: BaseAgent,  # Needed to know the expected input field
) -> dict | None:
    """Loads agent input from prompt, file, or JSON string. Handles errors and returns dict."""
    inputs_provided = sum(bool(arg) for arg in [prompt, input_file, input_json])

    if inputs_provided == 0:
        rprint(
            ":x: [bold red]Error:[/bold red] Must provide agent input via --prompt, --input-file, or --input-json."
        )
        raise typer.Exit(code=1)
    if inputs_provided > 1:
        rprint(
            ":x: [bold red]Error:[/bold red] Please provide input using only one of: --prompt, --input-file, --input-json."
        )
        raise typer.Exit(code=1)

    input_data: dict | None = None
    if input_file:
        try:
            with open(input_file) as f:
                input_data = json.load(f)
            rprint(f":floppy_disk: Loaded input from file: {input_file}")
        except json.JSONDecodeError as e:
            rprint(
                f":x: [bold red]Error:[/bold red] Failed to parse JSON input file: {e}"
            )
            raise typer.Exit(code=1) from e
        except Exception as e:
            rprint(f":x: [bold red]Error:[/bold red] Failed to read input file: {e}")
            raise typer.Exit(code=1) from e
    elif input_json:
        try:
            input_data = json.loads(input_json)
            rprint(":keyboard: Loaded input from JSON string.")
        except json.JSONDecodeError as e:
            rprint(
                f":x: [bold red]Error:[/bold red] Failed to parse JSON input string: {e}"
            )
            raise typer.Exit(code=1) from e
    elif prompt:
        rprint(f':speech_balloon: Using prompt: "{prompt}"')
        # Simplified: Default to using 'task_description' for prompt input.
        # This works for SecurityManager but might need adjustment for other agents.
        input_data = {"task_description": prompt}
        logger.info("Mapping --prompt input to 'task_description' field.")
        # Add a warning if the agent doesn't seem to expect 'task_description'
        input_schema_class = agent.input_schema_class
        if not input_schema_class or "task_description" not in getattr(
            input_schema_class, "model_fields", {}
        ):
            rprint(
                f":warning: [bold yellow]Warning:[/bold yellow] Agent '{agent.config.id}' input schema ('{getattr(input_schema_class, '__name__', 'N/A')}') "
                "might not directly use 'task_description'. Check agent requirements if prompt input fails."
            )

    return input_data


def _validate_cli_agent_input(agent: BaseAgent, input_data: dict) -> BaseModel | None:
    """Validates the raw input dict against the agent's input schema."""
    input_schema_class = agent.input_schema_class
    if not input_schema_class:
        rprint(
            f":x: [bold red]Error:[/bold red] Input schema '{getattr(agent.config, 'input_schema', 'N/A')}' class not resolved for agent '{getattr(agent.config, 'id', 'N/A')}'."
        )
        raise typer.Exit(code=1)

    try:
        validated_input = input_schema_class(**input_data)
        rprint(":white_check_mark: Input data validated successfully.")
        return validated_input
    except ValidationError as e:
        rprint(f":x: [bold red]Input Validation Error:[/bold red]\n{e}")
        raise typer.Exit(code=1) from e


def _handle_cli_output(output_obj: Any):
    """Formats and prints the agent output to the console."""
    if not isinstance(output_obj, BaseModel):
        rprint(
            f":warning: [bold yellow]Warning:[/bold yellow] Agent output type is '{type(output_obj).__name__}', expected Pydantic model."
        )
        # Attempt basic printing for non-model output
        output_json = json.dumps({"result": output_obj}, indent=2, default=str)
    else:
        try:
            # Dump Pydantic model to JSON
            output_json = json.dumps(
                output_obj.model_dump(mode="json"), indent=2, default=str
            )
        except Exception as e:
            rprint(f":x: [bold red]Error serializing agent output:[/bold red] {e}")
            output_json = json.dumps({"error": "Failed to serialize output"}, indent=2)

    rprint("\n[bold cyan]Agent Output:[/bold cyan]")
    # Use rich.syntax if available and safe
    try:
        from rich.syntax import Syntax

        syntax = Syntax(output_json, "json", theme="default", line_numbers=False)
        rprint(syntax)
    except ImportError:
        rprint(output_json)  # Fallback to basic print if rich syntax fails


# --- Agent Commands ---
@agents_app.command("list")
def list_agents_cli():
    """List all loaded and enabled agents."""
    rprint("[bold cyan]Available Agents:[/bold cyan]")
    try:
        # Ensure system is initialized (accessor functions handle this)
        agents_map = get_all_agents()
    except Exception as e:
        rprint(f":x: [bold red]Error loading agents during list:[/bold red] {e}")
        logger.exception("Agent loading failed for list command")
        raise typer.Exit(code=1) from e

    if not agents_map:
        rprint("  No agents loaded or enabled.")
        return

    for agent_id, agent_instance in agents_map.items():
        rprint(f"- [bold green]{agent_id}[/bold green]")
        # Safely access config attributes
        config = getattr(agent_instance, "config", None)
        if config:
            rprint(f"  Description: {getattr(config, 'description', 'N/A')}")
            rprint(
                f"  LLM: {getattr(config, 'llm_provider', 'Default')} / {getattr(config, 'model', 'Default')}"
            )
            rprint(f"  Input Schema: {getattr(config, 'input_schema', 'N/A')}")
            rprint(f"  Output Schema: {getattr(config, 'output_schema', 'N/A')}")
            tools_list = getattr(config, "tools", [])
            tool_aliases = [getattr(t, "alias", "N/A") for t in tools_list]
            rprint(f"  Tools: {', '.join(tool_aliases) if tool_aliases else 'None'}")
        else:
            rprint("  (Agent configuration details not available)")


@agents_app.command("run")
def run_agent_cli(
    agent_id: Annotated[str, typer.Argument(help="The ID of the agent to run.")],
    prompt: Annotated[
        Optional[str],
        typer.Option(
            "--prompt",
            "-p",
            help="Direct text prompt for the agent (alternative to JSON input).",
            show_default=False,
        ),
    ] = None,
    input_file: Annotated[
        Optional[Path],
        typer.Option(
            "--input-file",
            "-i",
            help="Path to a JSON file containing the input data.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            show_default=False,
        ),
    ] = None,
    input_json: Annotated[
        Optional[str],
        typer.Option(
            "--input-json",
            "-j",
            help="Input data as a JSON string.",
            show_default=False,
        ),
    ] = None,
    llm_provider: Annotated[
        Optional[str],
        typer.Option(
            "--llm-provider",
            help="Override the LLM provider for this run (e.g., 'openai', 'cerebras').",
            show_default=False,
        ),
    ] = None,
    # output_file: Annotated[ # Add back later if needed
    #     Optional[Path],
    #     typer.Option(
    #         "--output-file",
    #         "-o",
    #         help="Optional path to save the agent's JSON output.",
    #         writable=True,
    #         resolve_path=True,
    #     ),
    # ] = None,
):
    """Run a specific agent with the provided input (prompt, file, or JSON string)."""
    rprint(f"Attempting to run agent: [bold blue]{agent_id}[/bold blue]")

    # --- Get Agent --- #
    try:
        agent = get_agent(agent_id)
        if not agent:
            rprint(
                f":x: [bold red]Error:[/bold red] Agent '{agent_id}' not found or not loaded."
            )
            raise typer.Exit(code=1)
    except Exception as e:
        rprint(f":x: [bold red]Error getting agent '{agent_id}':[/bold red] {e}")
        logger.exception(f"Failed during get_agent for {agent_id}")
        raise typer.Exit(code=1) from e

    # --- Load & Validate Input --- #
    input_data = _load_cli_input(prompt, input_file, input_json, agent)
    if input_data is None:
        raise typer.Exit(code=1)

    validated_input = _validate_cli_agent_input(agent, input_data)
    if validated_input is None:
        raise typer.Exit(code=1)

    # --- Handle LLM Override (Placeholder/Warning) --- #
    if llm_provider:
        rprint(
            f":warning: [bold yellow]Warning:[/bold yellow] LLM provider override ('{llm_provider}') requested. "
            "This feature is not fully implemented in the agent core yet and will be ignored for this run."
        )
        # TODO: Implement actual LLM override logic within agent.run() or by temporarily reconfiguring the agent's client.

    # --- Execute Agent --- #
    try:
        rprint(":rocket: Running agent...")
        # NOTE: Pass llm_provider override here if agent.run supports it in the future
        output_obj = agent.run(validated_input)
        rprint(":tada: Agent execution completed!")

        # --- Handle Output --- #
        _handle_cli_output(output_obj)
        # TODO: Add saving to output_file if option is enabled

    except Exception as e:
        rprint(f":x: [bold red]Agent Execution Failed:[/bold red]\n  Error: {e}")
        logger.exception(f"Agent '{agent_id}' execution failed.")
        raise typer.Exit(code=1) from e


# --- Main Entry Point ---
if __name__ == "__main__":
    app()
