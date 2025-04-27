"""Unit tests for DomainWhoisAgent."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from agents.base import AgentConfig
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent
from schemas.domain_whois_schemas import DomainWhoisInput, DomainWhoisOutput
from schemas.whois_lookup_schemas import WhoisLookupOutput
from tools.whois_lookup_tool.whois_lookup_tool import WhoisLookupTool


# Mock LLM Client (Agent doesn't use it much, but needs initialization)
class MockLLMClient:
    def generate(self, *args, **kwargs) -> str:
        return "LLM Mock Response"


@pytest.fixture
def domain_whois_agent_config() -> AgentConfig:
    """Provides a valid AgentConfig for DomainWhoisAgent."""
    return AgentConfig(
        id="domain_whois_agent",
        description="Test WHOIS Agent",
        enabled=True,
        llm_provider="openai",  # Mocked anyway
        model="gpt-test",
        tools=[{"name": "whois_lookup_tool", "alias": "whois_lookup"}],
        parameters={},
        input_schema="DomainWhoisInput",
        output_schema="DomainWhoisOutput",
    )


@pytest.fixture
def mock_whois_tool() -> MagicMock:
    """Provides a mocked WhoisLookupTool instance."""
    mock = MagicMock(spec=WhoisLookupTool)
    # Configure the mock's execute method return value here for tests
    # Example success:
    mock.execute.return_value = WhoisLookupOutput(
        domain_name="example.com",
        registrar="Test Registrar",
        creation_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expiration_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        name_servers=["ns1.example.com"],
        status=["ok"],
        emails=["test@example.com"],
        dnssec="unsigned",
        updated_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        raw_data="RAW WHOIS DATA",
        error=None,
    )
    return mock


@pytest.fixture
def domain_whois_agent(
    domain_whois_agent_config, mock_whois_tool, monkeypatch
) -> DomainWhoisAgent:
    """Provides an initialized DomainWhoisAgent with mocked dependencies."""
    # Mock get_llm_client
    monkeypatch.setattr(
        "agents.domain_whois_agent.domain_whois_agent.get_llm_client",
        lambda x: MockLLMClient(),
    )

    # Provide the mock tool instance directly (initialization logic assumes tools are passed in)
    agent = DomainWhoisAgent(config=domain_whois_agent_config, tools=[mock_whois_tool])
    # Ensure the alias mapping is correct (BaseAgent init should handle this)
    assert "whois_lookup" in agent.tools
    return agent


def test_domain_whois_agent_success(domain_whois_agent, mock_whois_tool):
    """Test successful WHOIS lookup and processing."""
    input_data = DomainWhoisInput(domain="example.com")
    output = domain_whois_agent.run(input_data)

    mock_whois_tool.execute.assert_called_once()
    assert isinstance(output, DomainWhoisOutput)
    assert output.error is None
    assert output.domain_name == "example.com"
    assert output.registrar == "Test Registrar"
    assert output.creation_date == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert output.raw_data == "RAW WHOIS DATA"


def test_domain_whois_agent_tool_error(domain_whois_agent, mock_whois_tool):
    """Test when the WHOIS tool returns an error."""
    # Configure mock tool to return an error
    mock_whois_tool.execute.return_value = WhoisLookupOutput(
        domain_name="example.com",
        error="Tool failed lookup",
        raw_data="Tool raw error data",
    )

    input_data = DomainWhoisInput(domain="example.com")
    output = domain_whois_agent.run(input_data)

    mock_whois_tool.execute.assert_called_once()
    assert isinstance(output, DomainWhoisOutput)
    assert output.error == "Tool failed lookup"
    assert output.registrar is None  # Other fields should be None/default
    assert output.raw_data == "Tool raw error data"  # Error should propagate raw data


def test_domain_whois_agent_tool_exception(domain_whois_agent, mock_whois_tool):
    """Test when the WHOIS tool execution raises an exception."""
    mock_whois_tool.execute.side_effect = Exception("Tool crashed")

    input_data = DomainWhoisInput(domain="example.com")
    output = domain_whois_agent.run(input_data)

    mock_whois_tool.execute.assert_called_once()
    assert isinstance(output, DomainWhoisOutput)
    assert "WHOIS tool execution failed: Tool crashed" in output.error
    assert output.registrar is None
    assert output.raw_data is None  # No raw data if tool crashed


def test_domain_whois_agent_tool_missing(domain_whois_agent_config, monkeypatch):
    """Test when the required tool is missing from the agent's tools."""
    monkeypatch.setattr(
        "agents.domain_whois_agent.domain_whois_agent.get_llm_client",
        lambda x: MockLLMClient(),
    )

    # Initialize agent with an empty tool list
    agent = DomainWhoisAgent(config=domain_whois_agent_config, tools=[])

    input_data = DomainWhoisInput(domain="example.com")
    output = agent.run(input_data)

    assert isinstance(output, DomainWhoisOutput)
    assert "Required tool 'whois_lookup' not found" in output.error
    assert output.registrar is None
