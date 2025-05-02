"""Tests for the Domain Analyzer Agent."""

import pydantic_ai
import pytest
from unittest.mock import AsyncMock, patch
from pydantic_ai import capture_run_messages
from pydantic_ai.agent import AgentRunResult
from pydantic_ai.exceptions import (
    AgentRunError,
    ModelHTTPError,
    ModelRetry,
    UnexpectedModelBehavior,
    UsageLimitExceeded,
)
from pydantic_ai.models.test import TestModel
from pydantic_ai.tools import RunContext
import re

from agents.domain_analyzer_agent import domain_analyzer_agent, generate_domain_analysis, run_domain_analysis
from schemas.domain_analysis import (
    CertificateInfo,
    DNSSecurityInfo,
    DomainAnalysisResult,
    EmailSecurityInfo,
    IPWhoisInfo,
    ShodanHostInfo,
    VirusTotalUrlAnalysis,
)

MOCK_DOMAIN = "testdomain.com"
MOCK_IP = "192.0.2.1"

# Prevent actual LLM calls during tests
pydantic_ai.models.ALLOW_MODEL_REQUESTS = False


@pytest.fixture
def mock_test_model() -> TestModel:
    """Fixture to create a TestModel configured for the Domain Analyzer agent."""
    # Define the expected final output the model should generate
    # Note: TestModel primarily simulates the *final* step. Specifying intermediate
    # tool return values precisely often requires FunctionModel.
    test_model = TestModel(
        custom_output_args={
            "domain": MOCK_DOMAIN,
            "ip_info": {
                "ip_address": MOCK_IP,
                "asn": "64496",
                "asn_cidr": "192.0.2.0/24",
                "asn_country_code": "XX",
                "asn_description": "TEST-NET-1",
                "nets": [{"cidr": "192.0.2.0/24", "name": "TEST-NET"}],
            },
            "shodan_info": {
                "ip_address": MOCK_IP,
                "organization": "Test Shodan Org",
                "os": "TestOS",
                "ports": [80, 443, 8080],
                "tags": ["test-tag"],
                "vulns": ["CVE-2024-0001"],
                "last_update": "2024-01-02T00:00:00",
                "country_name": "Mock Country",
                "city": "Mock City",
            },
            "vt_analysis": {
                "url": f"http://{MOCK_DOMAIN}",
                "malicious_count": 1,
                "suspicious_count": 0,
                "harmless_count": 70,
                "undetected_count": 5,
                "last_analysis_date": "2024-01-03T00:00:00Z",
            },
            "certificates": [
                {
                    "issuer_name": "Test CA",
                    "common_names": ["testdomain.com", "www.testdomain.com"],
                    "not_before": "2023-01-01T00:00:00",
                    "not_after": "2024-01-01T00:00:00",
                    "serial_number": "ABCDEF0123",
                }
            ],
            "dns_security": {"dnssec_enabled": True},
            "email_security": {
                "spf_record": "v=spf1 -all",
                "spf_valid": True,
                "dmarc_record": "v=DMARC1; p=reject",
                "dmarc_policy": "reject",
                "dmarc_valid": True,
            },
            "analysis_summary": (
                "Domain analysis complete. Found IP, Shodan info (1 vuln), "
                "VT score (1 malicious), 1 certificate, DNSSEC enabled, and "
                "strict email security."
            ),
        },
        # call_tools='all' is the default, meaning TestModel will try to generate
        # valid inputs for all registered tools in sequence based on their schemas.
        # If specific intermediate results are needed, FunctionModel is required.
    )
    return test_model


@pytest.mark.asyncio
async def test_domain_analyzer_agent_success(mock_test_model):
    """Test the Domain Analyzer agent with successful tool calls."""
    # Override the agent's model with our TestModel
    with domain_analyzer_agent.override(model=mock_test_model):
        # Run the agent using the instruction function
        result = await domain_analyzer_agent.run(
            generate_domain_analysis(domain=MOCK_DOMAIN)
        )

    # --- Assertions --- #

    # Check the final output type and structure
    assert isinstance(result.output, DomainAnalysisResult)

    # Validate specific fields using direct comparison or dirty-equals for flexibility
    assert result.output.domain == MOCK_DOMAIN

    # IP Info
    assert isinstance(result.output.ip_info, IPWhoisInfo)
    assert result.output.ip_info.ip_address == MOCK_IP
    assert result.output.ip_info.asn == "64496"

    # Shodan Info
    assert isinstance(result.output.shodan_info, ShodanHostInfo)
    assert result.output.shodan_info.ip_address == MOCK_IP
    assert result.output.shodan_info.organization == "Test Shodan Org"
    assert result.output.shodan_info.ports == [80, 443, 8080]
    assert result.output.shodan_info.vulns == ["CVE-2024-0001"]

    # VirusTotal Info
    assert isinstance(result.output.vt_analysis, VirusTotalUrlAnalysis)
    assert result.output.vt_analysis.url == f"http://{MOCK_DOMAIN}"
    assert result.output.vt_analysis.malicious_count == 1
    assert result.output.vt_analysis.harmless_count == 70

    # Certificates
    assert isinstance(result.output.certificates, list)
    assert len(result.output.certificates) == 1
    assert isinstance(result.output.certificates[0], CertificateInfo)
    assert result.output.certificates[0].issuer_name == "Test CA"
    assert result.output.certificates[0].serial_number == "ABCDEF0123"

    # DNS Security
    assert isinstance(result.output.dns_security, DNSSecurityInfo)
    assert result.output.dns_security.dnssec_enabled is True

    # Email Security
    assert isinstance(result.output.email_security, EmailSecurityInfo)
    assert result.output.email_security.spf_record == "v=spf1 -all"
    assert result.output.email_security.dmarc_policy == "reject"

# Check usage (optional but good practice)
# assert result.usage.total_tokens > 0  # TestModel generates some usage
# assert result.usage.completion_tokens > 0
# assert result.usage.prompt_tokens > 0


@pytest.mark.asyncio
async def test_domain_analyzer_agent_partial_failure():
    """Test the agent when some tools return None or empty data."""
    # Configure TestModel to simulate a final output reflecting partial data.
    # Note: TestModel doesn't easily simulate intermediate tool *failures*
    # or specific None returns mid-run. FunctionModel is better suited for that.
    # Here, we just define the expected *final* output structure assuming
    # the agent's logic handles potential Nones from (unsimulated) tool calls.
    test_model_partial = TestModel(
        custom_output_args={
            "domain": MOCK_DOMAIN,
            "ip_info": None,
            "shodan_info": None,
            "vt_analysis": {"url": f"http://{MOCK_DOMAIN}", "malicious_count": None},
            "certificates": [],
            "dns_security": {"dnssec_enabled": False},
            "email_security": {
                "spf_record": None,
                "spf_valid": None,
                "dmarc_record": None,
                "dmarc_policy": None,
                "dmarc_valid": None,
            },
            "analysis_summary": (
                "Partial analysis for testdomain.com. IP lookup failed. "
                "VT report might be incomplete. No certificates found. DNSSEC is not enabled. "
                "No email security records found."
            ),
        },
    )

    with domain_analyzer_agent.override(model=test_model_partial):
        # Still run the agent via the user prompt method
        result = await domain_analyzer_agent.run(f"Analyze the domain: {MOCK_DOMAIN}")

    # Assertions for partial failure
    assert isinstance(result.output, DomainAnalysisResult)
    assert result.output.domain == MOCK_DOMAIN
    assert result.output.ip_info is None
    assert result.output.shodan_info is None  # Check Shodan
    assert isinstance(result.output.vt_analysis, VirusTotalUrlAnalysis)  # Check VT
    assert result.output.vt_analysis.malicious_count is None  # VT fields should be None
    assert result.output.certificates == []
    assert result.output.dns_security.dnssec_enabled is False
    assert result.output.email_security.spf_record is None
    assert result.output.email_security.dmarc_record is None
    assert "Partial analysis" in result.output.analysis_summary

    # Check usage (optional but good practice)
    # assert result.usage.total_tokens > 0  # TestModel generates some usage
    # assert result.usage.completion_tokens > 0
    # assert result.usage.prompt_tokens > 0 


# --- Tests for run_domain_analysis wrapper --- #


@pytest.mark.asyncio
@patch("agents.domain_analyzer_agent.domain_analyzer_agent.run")
async def test_run_domain_analysis_success(mock_agent_run):
    """Test the run_domain_analysis wrapper function on success."""
    # Mock the AgentRunResult
    mock_result = AsyncMock(spec=AgentRunResult)
    # Provide all required fields for the mock output
    mock_output = DomainAnalysisResult(
        domain=MOCK_DOMAIN, 
        analysis_summary="Minimal summary for test."
    )
    mock_result.output = mock_output
    mock_agent_run.return_value = mock_result

    # Call the wrapper
    result = await run_domain_analysis(MOCK_DOMAIN)

    # Assertions
    assert result == mock_output
    mock_agent_run.assert_awaited_once()
    # Check if the user prompt was passed correctly (adjust if needed)
    assert f"Analyze the domain: {MOCK_DOMAIN}" in mock_agent_run.call_args[0]


@pytest.mark.asyncio
@patch("agents.domain_analyzer_agent.domain_analyzer_agent.run")
async def test_run_domain_analysis_unexpected_output_type(mock_agent_run, caplog):
    """Test run_domain_analysis when agent returns an unexpected type."""
    mock_result = AsyncMock(spec=AgentRunResult)
    mock_result.output = "Just a string" # Unexpected type
    mock_agent_run.return_value = mock_result

    result = await run_domain_analysis(MOCK_DOMAIN)

    assert result is None
    mock_agent_run.assert_awaited_once()
    assert "Agent returned unexpected output type: <class 'str'>" in caplog.text


@pytest.mark.asyncio
@patch("agents.domain_analyzer_agent.domain_analyzer_agent.run")
@pytest.mark.parametrize(
    "exception_to_raise, log_message",
    [
        (UsageLimitExceeded("Test limit exceeded"), "Usage limit exceeded"),
        (
            UnexpectedModelBehavior("Test model behavior"),
            "Model behavior error",
        ),
        (
            # Provide model_name and status_code positionally again
            ModelHTTPError("test-model", 500),
            # Adjust assertion check string
            "Model HTTP error.*for testdomain.com",
        ),
        (AgentRunError("Test agent run error"), "Agent run error"),
        (ValueError("Some other error"), "Unexpected error"), # Test generic Exception
    ],
)
async def test_run_domain_analysis_exception_handling(
    mock_agent_run, caplog, exception_to_raise, log_message
):
    """Test run_domain_analysis catches various exceptions."""
    mock_agent_run.side_effect = exception_to_raise

    result = await run_domain_analysis(MOCK_DOMAIN)

    assert result is None
    mock_agent_run.assert_awaited_once()
    # Use regex search for more flexible log checking
    assert re.search(log_message, caplog.text), \
        f"Expected log pattern '{log_message}' not found in logs: {caplog.text}"