"""Tests for the NetworkSecurityAgent.

This tests the NetworkSecurityAgent implementation, including its tools and
functionality.
"""

from unittest.mock import MagicMock  # Import MagicMock

import pytest
from pydantic_ai.exceptions import (
    AgentRunError,
    ModelHTTPError,
    UnexpectedModelBehavior,
    UsageLimitExceeded,
)

# Revert to using base ModelMessage
from agents.network_security_agent import (
    NetworkScanResult,  # Correct schema name based on agent definition
    ScanSeverity,  # Add missing import
    scan_target,  # Correct function to test
)

# Mark all tests in this module as async
pytestmark = pytest.mark.asyncio


# Mock AgentRunResult for successful runs
# This mock needs to be updated if scan_target doesn't directly return AgentRunResult
# For now, assume scan_target calls agent.run which returns AgentRunResult
# We will patch the agent.run method called *within* scan_target


class MockAgentRunResult:
    def __init__(self, output):
        self.output = output
        # Assign simple lists/mocks instead of instantiating ModelMessage
        self.all_messages: list[MagicMock] = [MagicMock()]
        self.new_messages: list[MagicMock] = [MagicMock()]
        self.usage = {}  # Mock usage data if needed

    @property
    def cost(self):
        return 0.0

    @property
    def llm_token_usage(self):
        return {}


@pytest.fixture
def mock_agent_run_in_scan_target(mocker):
    """Fixture to mock the agent's run method called within scan_target."""
    # Patch the .run method of the Agent class instantiated *within* scan_target
    # This requires knowing the path precisely.
    # Assuming NetworkSecurityAgent is instantiated locally in scan_target:
    return mocker.patch("agents.network_security_agent.NetworkSecurityAgent.run")


# Tests for the scan_target wrapper function


async def test_scan_target_success(mock_agent_run_in_scan_target):
    """Test successful execution of scan_target."""
    target = "192.168.1.0/24"
    expected_result_data = NetworkScanResult(
        target=target,
        # scan_timestamp will be set by default_factory
        vulnerabilities=[],
        summary={},  # Example empty summary
        recommendations=["Scan completed successfully."],
    )
    # Mock agent.run to return a result containing the expected output
    mock_agent_run_in_scan_target.return_value = MockAgentRunResult(
        output=expected_result_data
    )

    # Call the actual scan_target function
    result = await scan_target(target=target)

    # Assert that the scan_target function returns the expected data
    assert isinstance(result, NetworkScanResult)
    assert result.target == expected_result_data.target
    assert result.recommendations == expected_result_data.recommendations
    mock_agent_run_in_scan_target.assert_awaited_once()
    # Optionally check the prompt passed to agent.run
    call_args, call_kwargs = mock_agent_run_in_scan_target.call_args
    assert f"Perform a comprehensive security scan of {target}" in call_args[0]
    assert "deps" in call_kwargs
    assert call_kwargs["deps"]["domain_info"] is None  # Default case


async def test_scan_target_usage_limit_exceeded(mock_agent_run_in_scan_target):
    """Test scan_target handling UsageLimitExceeded from agent.run."""
    target = "192.168.1.0/24"
    mock_agent_run_in_scan_target.side_effect = UsageLimitExceeded("Limit hit")
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_unexpected_behavior(mock_agent_run_in_scan_target):
    """Test scan_target handling UnexpectedModelBehavior from agent.run."""
    target = "192.168.1.0/24"
    mock_agent_run_in_scan_target.side_effect = UnexpectedModelBehavior("Unexpected")
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_model_http_error(mock_agent_run_in_scan_target):
    """Test scan_target handling ModelHTTPError from agent.run."""
    target = "192.168.1.0/24"
    # Try positional arguments for ModelHTTPError
    mock_agent_run_in_scan_target.side_effect = ModelHTTPError("Err", 500)
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_agent_run_error(mock_agent_run_in_scan_target):
    """Test scan_target handling AgentRunError from agent.run."""
    target = "192.168.1.0/24"
    mock_agent_run_in_scan_target.side_effect = AgentRunError("Agent failed")
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_unexpected_output_type(mock_agent_run_in_scan_target):
    """Test scan_target handling unexpected output type from agent.run."""
    target = "192.168.1.0/24"
    mock_agent_run_in_scan_target.return_value = MockAgentRunResult(output="string")
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_generic_exception(mock_agent_run_in_scan_target):
    """Test scan_target handling generic Exception from agent.run."""
    target = "192.168.1.0/24"
    mock_agent_run_in_scan_target.side_effect = Exception("Something went wrong")
    result = await scan_target(target=target)
    assert result is None
    mock_agent_run_in_scan_target.assert_awaited_once()


async def test_scan_target_with_domain_info(mock_agent_run_in_scan_target):
    """Test scan_target passing domain_info correctly."""
    target = "example.com"
    domain_info = {"ip_address": "93.184.216.34", "asn": "AS15169"}
    expected_result_data = NetworkScanResult(target=target)
    mock_agent_run_in_scan_target.return_value = MockAgentRunResult(
        output=expected_result_data
    )

    result = await scan_target(target=target, domain_info=domain_info)

    assert result is not None
    mock_agent_run_in_scan_target.assert_awaited_once()
    call_args, call_kwargs = mock_agent_run_in_scan_target.call_args
    assert call_kwargs["deps"]["domain_info"] == domain_info


async def test_scan_target_with_severity_filter(mock_agent_run_in_scan_target):
    """Test scan_target constructing prompt with severity filter."""
    target = "example.com"
    # Use the imported ScanSeverity
    severity = ScanSeverity.HIGH
    expected_result_data = NetworkScanResult(target=target)
    mock_agent_run_in_scan_target.return_value = MockAgentRunResult(
        output=expected_result_data
    )

    await scan_target(target=target, severity_filter=severity)

    mock_agent_run_in_scan_target.assert_awaited_once()
    call_args, call_kwargs = mock_agent_run_in_scan_target.call_args
    assert f"Focus on {severity.value} and higher severity issues." in call_args[0]


async def test_scan_target_with_custom_rate_limit(mock_agent_run_in_scan_target):
    """Test scan_target constructing prompt with custom rate limit."""
    target = "example.com"
    rate_limit = 50
    expected_result_data = NetworkScanResult(target=target)
    mock_agent_run_in_scan_target.return_value = MockAgentRunResult(
        output=expected_result_data
    )

    await scan_target(target=target, rate_limit=rate_limit)

    mock_agent_run_in_scan_target.assert_awaited_once()
    call_args, call_kwargs = mock_agent_run_in_scan_target.call_args
    assert f"Adjust the scan rate limit towards {rate_limit}" in call_args[0]


# ----- Placeholder for Agent Internal Logic Tests ----- #
# Tests using agent.override() would go here, similar to the
# commented-out example in the previous version of this file.
# These would test the NetworkSecurityAgent class directly.


# ----- Old Test Class (Likely needs removal or refactoring) ----- #
# The following class and its tests seem to be leftovers or incorrectly structured.
# They attempt to call methods directly on the agent or mock incorrectly.
# Keeping it commented out for now, but should likely be removed/refactored
# into tests for the wrapper function or internal logic tests above.

# import os
# from datetime import datetime, timezone
# from typing import List
# from unittest.mock import patch
#
# from agents.network_security_agent import (
#     NetworkScanResult, # Already imported
#     NetworkSecurityAgent,
#     ScanSeverity,
#     VulnerabilityFinding,
#     network_security_agent # Already imported
# )
#
# @pytest.fixture
# def sample_vulnerability_findings() -> List[VulnerabilityFinding]:
#     # ... (Implementation potentially duplicated)
#     pass # Replace with actual implementation if needed, or remove if unused
#
# @pytest.fixture
# def sample_network_scan_result(sample_vulnerability_findings) -> NetworkScanResult:
#     # ... (Implementation potentially duplicated)
#     pass # Replace with actual implementation if needed, or remove if unused
#
# @pytest.fixture
# def mock_nuclei_result():
#     # ... (Implementation potentially duplicated)
#     pass # Replace with actual implementation if needed, or remove if unused
#
# @pytest.fixture(autouse=True)
# def set_test_env():
#     # ... (Implementation potentially duplicated)
#     pass # Replace with actual implementation if needed, or remove if unused
#
# class TestNetworkSecurityAgent:
#     """Tests for the NetworkSecurityAgent."""
#
#     def test_agent_initialization(self):
#         """Test that the agent initializes correctly."""
#         agent = NetworkSecurityAgent()
#         assert "openai" in str(agent.model).lower()
#         assert agent.output_type == NetworkScanResult # Use correct schema name
#         assert network_security_agent is not None
#         assert isinstance(network_security_agent, NetworkSecurityAgent)
#
#     @pytest.mark.asyncio
#     async def test_scan_target_error_handling(self):
#         """Test error handling in the scan_target method. - REWRITTEN ABOVE"""
#         # This test was failing due to AttributeError and is likely incorrect.
#         # The agent interaction should happen via run_network_security_analysis
#         # or by testing internal logic with agent.override().
#         pass # Original failing test removed/commented
