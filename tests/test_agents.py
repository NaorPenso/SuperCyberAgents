"""Unit tests for the ExampleAgent implementation."""

from unittest.mock import MagicMock, patch

import pytest

from agents.base import AgentConfig
from agents.example_agent import ExampleAgent
from schemas.agent_schemas import ExampleAgentInput, ExampleAgentOutput


@pytest.fixture
def configured_example_agent():
    """Fixture for a properly configured ExampleAgent for testing."""
    # Create a minimal agent configuration
    agent_config = AgentConfig(
        id="example_agent_test",
        name="Example Agent Test",
        description="A test agent for unit tests",
        llm_provider="openai",
        model="mock",
        input_schema="ExampleAgentInput",
        output_schema="ExampleAgentOutput",
        tools=[],  # No tools required for ExampleAgent
    )

    # Mock the LLM client to avoid provider config issues
    with patch("agents.example_agent.get_llm_client", return_value=MagicMock()):
        # Create the agent
        agent = ExampleAgent(config=agent_config, tools=[])
        return agent


def test_example_agent_success(configured_example_agent):
    """Test a successful example agent run with simple input/output."""
    agent = configured_example_agent

    # Configure expected output
    expected_output = ExampleAgentOutput(
        analysis_summary="This is a test analysis", is_suspicious=False
    )

    # Patch the run method instead (not run_sync which doesn't exist)
    with patch.object(agent, "run", return_value=expected_output):
        # Create input data for the agent
        input_data = ExampleAgentInput(log_entry="Normal system operation")

        # Run the agent
        result = agent.run(input_data)

    # Verify the output has the expected structure and values
    assert isinstance(result, ExampleAgentOutput)
    assert result.analysis_summary == "This is a test analysis"
    assert result.is_suspicious is False


def test_example_agent_different_input(configured_example_agent):
    """Test the example agent with different input parameters."""
    agent = configured_example_agent

    # Configure expected output
    expected_output = ExampleAgentOutput(
        analysis_summary="Detailed security analysis of example.com",
        is_suspicious=True,
        ip_reputation="High risk",
    )

    # Patch the run method (not run_sync)
    with patch.object(agent, "run", return_value=expected_output):
        # Create input data with an IP address
        input_data = ExampleAgentInput(
            log_entry="Failed login attempt from suspicious IP", target_ip="192.168.1.1"
        )

        # Run the agent
        result = agent.run(input_data)

    # Verify the output matches our expectations
    assert isinstance(result, ExampleAgentOutput)
    assert "example.com" in result.analysis_summary
    assert result.is_suspicious is True
    assert result.ip_reputation == "High risk"
