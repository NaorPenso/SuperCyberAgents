"""Tests for the Typer CLI application."""

import json
from pathlib import Path
from typing import ClassVar, List

import pytest
from typer.testing import CliRunner

# Mock data for agent/tool registries used by CLI
# These mocks assume initialize_system is called before CLI commands run
# We need to mock the state *after* initialization for CLI tests.


@pytest.fixture(scope="module", autouse=True)
def mock_cli_initialization(module_mocker):
    """Mock the state that the CLI expects after initialization."""

    # Define a simple mock schema class locally for the test
    class CliInputSchema:
        def __init__(self, **kwargs):
            self.data = kwargs
            if "invalid_cli" in kwargs:
                raise ValueError("Invalid CLI input schema")

        def get(self, key):
            return self.data.get(key)

    # Mock get_agent and get_all_agents as used by CLI commands
    class MockCliAgentConfig:
        id = "cli-agent"
        description = "CLI Test Agent"
        llm_provider = "cli_provider"
        model = "cli_model"
        input_schema = "CliInputSchema"
        output_schema = "CliOutputSchema"
        input_schema_class = CliInputSchema  # Use the locally defined class
        tools: ClassVar[List[object]] = [
            type("ToolRef", (), {"name": "cli_tool", "alias": "cli_tool"})
        ]

    class MockCliOutput:
        def model_dump(self, mode=None):  # Match Pydantic v2 signature if needed
            return {"cli_result": "cli success"}

    class MockCliAgent:
        config = MockCliAgentConfig()

        def run(self, input_obj, settings=None):  # Match expected signature
            if input_obj.data.get("cli_fail"):  # Trigger failure
                raise RuntimeError("CLI agent simulated error")
            return MockCliOutput()

    mock_cli_agents = {"cli-agent": MockCliAgent()}

    # Mock the functions called by the CLI module (cli.main)
    module_mocker.patch("cli.main.initialize_system", return_value=None)
    module_mocker.patch("cli.main.get_agent", mock_cli_agents.get)
    module_mocker.patch("cli.main.get_all_agents", return_value=mock_cli_agents)

    # Mock schema lookup used by CLI
    module_mocker.patch(
        "cli.main._get_schema_class_cli",
        lambda name: CliInputSchema if name == "CliInputSchema" else None,
    )


# --- CLI Runner Fixture ---
@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


# --- Tests ---
def test_cli_agent_list(cli_runner):
    """Test the `agent list` command."""
    # Import app here to ensure mocks are applied
    from cli.main import app

    result = cli_runner.invoke(app, ["agent", "list"])
    assert result.exit_code == 0
    assert "cli-agent" in result.stdout
    assert "CLI Test Agent" in result.stdout
    assert "Input Schema: CliInputSchema" in result.stdout


def test_cli_agent_run_success(cli_runner, tmp_path):
    """Test the `agent run` command successfully."""
    from cli.main import app

    # Create dummy input file
    input_data = {"data": "cli input"}
    input_file: Path = tmp_path / "cli_input.json"
    input_file.write_text(json.dumps(input_data))

    result = cli_runner.invoke(
        app, ["agent", "run", "cli-agent", "--input-file", str(input_file)]
    )

    assert result.exit_code == 0
    assert "Agent execution completed!" in result.stdout
    assert '{"cli_result": "cli success"}' in result.stdout.replace(
        "\n", ""
    )  # Check output JSON


def test_cli_agent_run_agent_not_found(cli_runner, tmp_path):
    """Test `agent run` when agent ID does not exist."""
    from cli.main import app

    input_file: Path = tmp_path / "dummy.json"
    input_file.write_text("{}")

    result = cli_runner.invoke(
        app, ["agent", "run", "nonexistent-agent", "--input-file", str(input_file)]
    )

    assert result.exit_code == 1
    assert "Agent 'nonexistent-agent' not found" in result.stdout


def test_cli_agent_run_input_file_not_found(cli_runner):
    """Test `agent run` when input file does not exist."""
    from cli.main import app

    result = cli_runner.invoke(
        app, ["agent", "run", "cli-agent", "--input-file", "nonexistent.json"]
    )

    assert result.exit_code != 0  # Typer handles this, exit code might be 2
    assert "Invalid value" in result.stdout  # Typer's error message
    assert "does not exist" in result.stdout


def test_cli_agent_run_invalid_json(cli_runner, tmp_path):
    """Test `agent run` with a malformed JSON input file."""
    from cli.main import app

    input_file: Path = tmp_path / "invalid.json"
    input_file.write_text("this is not json")

    result = cli_runner.invoke(
        app, ["agent", "run", "cli-agent", "--input-file", str(input_file)]
    )

    assert result.exit_code == 1
    assert "Failed to parse JSON input file" in result.stdout


def test_cli_agent_run_schema_validation_error(cli_runner, tmp_path):
    """Test `agent run` when input data fails schema validation."""
    from cli.main import app

    input_data = {"invalid_cli": True}  # Triggers validation error in mock schema
    input_file: Path = tmp_path / "schema_fail.json"
    input_file.write_text(json.dumps(input_data))

    result = cli_runner.invoke(
        app, ["agent", "run", "cli-agent", "--input-file", str(input_file)]
    )

    assert result.exit_code == 1
    assert "Input Validation Error" in result.stdout


def test_cli_agent_run_execution_error(cli_runner, tmp_path):
    """Test `agent run` when the agent execution raises an error."""
    from cli.main import app

    input_data = {"cli_fail": True}  # Triggers runtime error in mock agent
    input_file: Path = tmp_path / "runtime_fail.json"
    input_file.write_text(json.dumps(input_data))

    result = cli_runner.invoke(
        app, ["agent", "run", "cli-agent", "--input-file", str(input_file)]
    )

    assert result.exit_code == 1
    assert "Agent Execution Error" in result.stdout
    assert "CLI agent simulated error" in result.stdout
