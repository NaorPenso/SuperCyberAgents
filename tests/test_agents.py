"""Unit tests for Agents."""

import pytest
from pydantic import ValidationError

from agents.base import AgentConfig
from agents.example_agent import ExampleAgent
from schemas.agent_schemas import ExampleAgentInput, ExampleAgentOutput
from schemas.tool_schemas import IPLookupOutput


# Mock LLM Client
class MockLLMClient:
    def generate(self, prompt: str, model: str, **kwargs) -> str:
        if "error" in prompt.lower():
            raise ValueError("Simulated LLM error")
        return "LLM analysis summary based on prompt."


# Mock Tool
class MockIPLookupTool:
    config = None  # Not strictly needed for mock

    def execute(self, input_data) -> IPLookupOutput:
        if input_data.ip_address == "1.1.1.1":
            return IPLookupOutput(ip_address="1.1.1.1", reputation="benign", details={})
        elif input_data.ip_address == "9.9.9.9":
            raise ConnectionError("Simulated tool connection error")
        else:
            return IPLookupOutput(
                ip_address=str(input_data.ip_address),
                reputation="malicious",
                details={},
            )


@pytest.fixture
def example_agent_config() -> AgentConfig:
    """Provides a valid AgentConfig for ExampleAgent."""
    return AgentConfig(
        id="example-agent",
        description="Test Agent",
        enabled=True,
        llm_provider="openai",  # Mocked anyway
        model="gpt-test",
        tools=[{"name": "ip_lookup_tool", "alias": "ip_lookup"}],
        parameters={"temperature": 0.1},
        input_schema="ExampleAgentInput",
        output_schema="ExampleAgentOutput",
    )


@pytest.fixture
def example_agent(example_agent_config, monkeypatch) -> ExampleAgent:
    """Provides an initialized ExampleAgent with mocked dependencies."""
    # Mock the get_llm_client function in the agent's module
    monkeypatch.setattr(
        "agents.example_agent.get_llm_client", lambda x: MockLLMClient()
    )

    # Provide the mock tool instance
    mock_tool_instance = MockIPLookupTool()
    agent = ExampleAgent(config=example_agent_config, tools=[mock_tool_instance])
    # Ensure the tool is mapped correctly by alias in the agent
    agent.tools = {"ip_lookup": mock_tool_instance}
    return agent


def test_example_agent_config_validation():
    """Test that AgentConfig validation works."""
    valid_data = {
        "id": "valid-agent",
        "description": "Valid",
        "llm_provider": "openai",
        "model": "gpt-4",
        "input_schema": "In",
        "output_schema": "Out",
    }
    cfg = AgentConfig(**valid_data)
    assert cfg.id == "valid-agent"

    invalid_data = {"id": "invalid"}  # Missing required fields
    with pytest.raises(ValidationError):
        AgentConfig(**invalid_data)

    invalid_provider = valid_data.copy()
    invalid_provider["llm_provider"] = "unknown_provider"
    with pytest.raises(ValidationError):
        AgentConfig(**invalid_provider)


def test_example_agent_run_success(example_agent):
    """Test successful execution of ExampleAgent."""
    input_data = ExampleAgentInput(log_entry="Some log data", target_ip="1.1.1.1")
    output = example_agent.run(input_data)

    assert isinstance(output, ExampleAgentOutput)
    assert "LLM analysis summary" in output.analysis_summary
    assert output.ip_reputation == "benign"
    assert not output.is_suspicious  # Default log + benign IP


def test_example_agent_run_suspicious_log(example_agent):
    """Test when log entry indicates suspicion."""
    input_data = ExampleAgentInput(
        log_entry="ERROR: Failed login attempt", target_ip="1.1.1.1"
    )
    output = example_agent.run(input_data)
    assert output.is_suspicious


def test_example_agent_run_suspicious_ip(example_agent):
    """Test when IP lookup tool indicates suspicion."""
    input_data = ExampleAgentInput(log_entry="Normal log entry", target_ip="8.8.8.8")
    output = example_agent.run(input_data)
    assert output.ip_reputation == "malicious"
    assert output.is_suspicious


def test_example_agent_run_no_ip(example_agent):
    """Test execution when no target IP is provided."""
    input_data = ExampleAgentInput(log_entry="Log without IP")
    output = example_agent.run(input_data)
    assert output.ip_reputation is None
    assert not output.is_suspicious


def test_example_agent_run_llm_error(example_agent, caplog):
    """Test agent behavior when LLM fails."""
    input_data = ExampleAgentInput(log_entry="Trigger LLM error", target_ip="1.1.1.1")
    output = example_agent.run(input_data)

    assert "Error during LLM analysis" in output.analysis_summary
    assert output.ip_reputation == "benign"  # Tool should still run
    assert "LLM generation failed" in caplog.text


def test_example_agent_run_tool_error(example_agent, caplog):
    """Test agent behavior when a tool fails."""
    input_data = ExampleAgentInput(
        log_entry="Normal log", target_ip="9.9.9.9"
    )  # This IP triggers tool error
    output = example_agent.run(input_data)

    assert output.ip_reputation is None  # Tool failed, no reputation
    assert "LLM analysis summary" in output.analysis_summary  # LLM should still run
    assert "IP lookup tool execution failed" in caplog.text
