"""Test suite for the Domain WHOIS Agent."""

from unittest.mock import MagicMock, patch

import pytest

from agents.base import AgentConfig, ToolConfig
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent
from schemas.domain_whois_schemas import DomainWhoisInput, DomainWhoisOutput
from schemas.whois_lookup_schemas import WhoisLookupOutput


@pytest.fixture
def configured_domain_whois_agent():
    """Fixture for a properly configured DomainWhoisAgent."""
    # Create a minimal tool configuration
    tool_config = ToolConfig(
        name="whois_lookup_tool",  # Must match pattern ^[a-z0-9_]+$
        description="Looks up WHOIS information for a domain",
        input_schema="WhoisLookupInput",
        output_schema="WhoisLookupOutput",
    )

    # Create a minimal agent configuration
    agent_config = AgentConfig(
        id="domain_whois_agent",
        name="Domain WHOIS Agent",
        description="Retrieves and analyzes WHOIS information",
        llm_provider="openai",
        model="mock",
        input_schema="DomainWhoisInput",
        output_schema="DomainWhoisOutput",
        tools=[],  # We'll pass the tool instance directly
    )

    # Create a mock whois_lookup_tool
    mock_tool = MagicMock()
    mock_tool.id = "whois_lookup_tool"
    mock_tool.name = "whois_lookup_tool"
    mock_tool.config = tool_config

    # Mock the LLM client to avoid provider config issues
    with patch(
        "agents.domain_whois_agent.domain_whois_agent.get_llm_client",
        return_value=MagicMock(),
    ):
        # Create the agent with the mock tool
        agent = DomainWhoisAgent(config=agent_config, tools=[mock_tool])

        # The agent expects tools to be accessible by alias
        agent.tools = {"whois_lookup": mock_tool}

        return agent


def test_domain_whois_agent_success(configured_domain_whois_agent):
    """Test the domain WHOIS agent with a successful tool response."""
    agent = configured_domain_whois_agent

    # Configure a mock whois tool result
    mock_whois_output = WhoisLookupOutput(
        domain_name="example.com",
        registrar="Example Registrar",
        creation_date="2023-01-01",
        expiration_date="2024-01-01",
        name_servers=["ns1.example.com", "ns2.example.com"],
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        raw_data="Raw WHOIS data here",
    )

    # Make the mock tool return our configured output
    agent.tools["whois_lookup"].execute.return_value = mock_whois_output

    # Create input for the agent
    input_data = DomainWhoisInput(domain="example.com")

    # Run the agent
    result = agent.run(input_data)

    # Check that the agent called the tool with the right input
    agent.tools["whois_lookup"].execute.assert_called_once()

    # Check that the output has the expected structure
    assert isinstance(result, DomainWhoisOutput)
    assert result.domain_name == "example.com"
    assert result.registrar == "Example Registrar"
    assert len(result.name_servers) == 2


def test_domain_whois_agent_tool_missing():
    """Test the agent behavior when the required tool is missing."""
    # Create an agent without the required tool
    agent_config = AgentConfig(
        id="domain_whois_agent_no_tool",
        name="Domain WHOIS Agent (No Tool)",
        description="Agent without required tool",
        llm_provider="openai",
        model="mock",
        input_schema="DomainWhoisInput",
        output_schema="DomainWhoisOutput",
        tools=[],
    )

    # Expected behavior seems to have changed - the agent no longer checks for required tools
    # Let's just test that it can be instantiated without error for now
    with patch(
        "agents.domain_whois_agent.domain_whois_agent.get_llm_client",
        return_value=MagicMock(),
    ):
        domain_whois_agent = DomainWhoisAgent(config=agent_config, tools=[])

        # Test the error case when running without the required tool
        input_data = DomainWhoisInput(domain="example.com")
        result = domain_whois_agent.run(input_data)

        # Check that an error is returned in the output
        assert result.error is not None
        assert "whois_lookup" in result.error
