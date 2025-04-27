"""Unit tests for Tools."""

import pytest
import requests
from pydantic import ValidationError

from agents.base import ToolConfig  # Import ToolConfig from where it's defined
from schemas.tool_schemas import IPLookupInput, IPLookupOutput
from tools.ip_lookup_tool import IPLookupTool


@pytest.fixture
def ip_lookup_config() -> ToolConfig:
    """Provides a valid ToolConfig for IPLookupTool."""
    return ToolConfig(
        name="ip_lookup_tool",
        description="Test Tool",
        endpoint="http://mock-api.test/lookup",
        auth_required=True,
        timeout_sec=5,
        input_schema="IPLookupInput",
        output_schema="IPLookupOutput",
    )


def test_tool_config_validation():
    """Test ToolConfig validation."""
    valid_data = {
        "name": "valid_tool",
        "description": "Desc",
        "input_schema": "In",
        "output_schema": "Out",
    }
    cfg = ToolConfig(**valid_data)
    assert cfg.name == "valid_tool"

    invalid_data = {"name": "invalid"}  # Missing required fields
    with pytest.raises(ValidationError):
        ToolConfig(**invalid_data)

    invalid_name = valid_data.copy()
    invalid_name["name"] = "Invalid Name"
    with pytest.raises(ValidationError):  # Name must match pattern
        ToolConfig(**invalid_name)


def test_ip_lookup_tool_success(ip_lookup_config, monkeypatch):
    """Test successful execution of IPLookupTool."""
    # Mock environment variable for API key
    monkeypatch.setenv("IP_LOOKUP_API_KEY", "test-key")

    # Mock requests.get
    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"reputation": "malicious", "details": {"source": "mock"}}

    def mock_get(url, params, headers, timeout):
        assert url == ip_lookup_config.endpoint
        assert params == {"ip": "8.8.8.8"}
        assert headers["Authorization"] == "Bearer test-key"
        assert timeout == ip_lookup_config.timeout_sec
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)

    tool = IPLookupTool(ip_lookup_config)
    input_data = IPLookupInput(ip_address="8.8.8.8")
    output = tool.execute(input_data)

    assert isinstance(output, IPLookupOutput)
    assert output.reputation == "malicious"
    assert output.details == {"source": "mock"}
    assert output.ip_address == "8.8.8.8"


def test_ip_lookup_tool_api_error(ip_lookup_config, monkeypatch):
    """Test IPLookupTool handling API errors."""
    monkeypatch.setenv("IP_LOOKUP_API_KEY", "test-key")

    # Mock requests.get to raise an error
    def mock_get_error(url, params, headers, timeout):
        raise requests.exceptions.ConnectionError("Failed to connect")

    monkeypatch.setattr(requests, "get", mock_get_error)

    tool = IPLookupTool(ip_lookup_config)
    input_data = IPLookupInput(ip_address="8.8.8.8")
    output = tool.execute(input_data)

    assert output.reputation == "error"
    assert "API request failed" in output.details["error"]


def test_ip_lookup_tool_missing_key(ip_lookup_config, monkeypatch):
    """Test IPLookupTool when auth is required but key is missing."""
    # Ensure env var is not set
    monkeypatch.delenv("IP_LOOKUP_API_KEY", raising=False)

    tool = IPLookupTool(ip_lookup_config)
    input_data = IPLookupInput(ip_address="8.8.8.8")
    output = tool.execute(input_data)

    assert output.reputation == "error"
    assert "API key not configured" in output.details["error"]


def test_ip_lookup_tool_no_auth_needed(ip_lookup_config, monkeypatch):
    """Test tool execution when auth is not required."""
    # Modify config for this test
    ip_lookup_config.auth_required = False

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"reputation": "benign"}

    def mock_get_no_auth(url, params, headers, timeout):
        assert "Authorization" not in headers  # Key should not be sent
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get_no_auth)

    tool = IPLookupTool(ip_lookup_config)
    input_data = IPLookupInput(ip_address="1.1.1.1")
    output = tool.execute(input_data)

    assert output.reputation == "benign"


def test_ip_lookup_tool_no_endpoint(ip_lookup_config):
    """Test tool behavior when endpoint is not configured."""
    ip_lookup_config.endpoint = None  # Simulate missing endpoint

    tool = IPLookupTool(ip_lookup_config)
    input_data = IPLookupInput(ip_address="1.1.1.1")
    output = tool.execute(input_data)

    assert output.reputation == "error"
    assert "Tool endpoint not configured" in output.details["error"]
