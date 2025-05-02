"""Tests for Pydantic schemas."""

import pytest
from pydantic import ValidationError

# Import all schema classes that need testing
from schemas.agent_schemas import ExampleAgentInput, ExampleAgentOutput
from schemas.delegate_task_schemas import DelegateTaskInput, DelegateTaskOutput
from schemas.security_manager_schemas import (
    AnalysisRequest,
    AnalysisResult,
    MonitorSpec,
    ThreatLevel,
)
from schemas.shodan_schemas import ShodanHostOutput, ShodanOutput
from schemas.subdomain_finder_schemas import SubdomainFinderInput, SubdomainFinderOutput
from schemas.template_tool_schemas import TemplateToolInput, TemplateToolOutput
from schemas.tool_schemas import IPLookupInput, IPLookupOutput
from schemas.virustotal_schemas import VirusTotalInput, VirusTotalOutput
from schemas.whois_lookup_schemas import WhoisLookupInput, WhoisLookupOutput

# TODO: Add tests for schemas, e.g., validation logic.


def test_placeholder():
    """Placeholder test."""
    assert True


# --- Agent Schemas --- #


def test_example_agent_input():
    """Test ExampleAgentInput schema."""
    data = {"log_entry": "Error message", "target_ip": "1.2.3.4"}
    assert ExampleAgentInput(**data)


def test_example_agent_output():
    """Test ExampleAgentOutput schema."""
    data = {
        "analysis_summary": "Looks bad",
        "ip_reputation": "Malicious",
        "is_suspicious": True,
    }
    # processed_at has a default factory
    output = ExampleAgentOutput(**data)
    assert output.processed_at is not None


# --- Delegate Task Schemas --- #


def test_delegate_input():
    data = {"agent_id": "agent1", "agent_input": {"task": "do stuff"}}
    assert DelegateTaskInput(**data)


def test_delegate_output():
    data_success = {
        "agent_id": "agent1",
        "status": "success",
        "result": {"output": "done"},
    }
    data_error = {"agent_id": "agent1", "status": "error", "error_message": "It failed"}
    assert DelegateTaskOutput(**data_success)
    assert DelegateTaskOutput(**data_error)


# --- Security Manager Schemas --- #


def test_monitor_spec():
    data = {"monitor_type": "log", "config": {"path": "/var/log"}}
    assert MonitorSpec(**data)


def test_analysis_request():
    spec = MonitorSpec(monitor_type="log", config={})
    data = {"request_id": "r1", "spec": spec}
    assert AnalysisRequest(**data)


def test_analysis_result():
    data = {
        "request_id": "r1",
        "threat_level": ThreatLevel.MEDIUM,
        "summary": "Potential issue found.",
        "details": [{"finding": "detail"}],
    }
    assert AnalysisResult(**data)


# --- Shodan Schemas --- #


def test_shodan_host_output():
    data = {"ip_str": "1.1.1.1", "port": 80, "data": "details"}
    assert ShodanHostOutput(**data)


def test_shodan_output():
    host = ShodanHostOutput(ip_str="1.1.1.1", port=80, data="")
    data = {"query": "apache", "matches": [host]}
    assert ShodanOutput(**data)


# --- Subdomain Finder Schemas --- #


def test_subdomain_finder_input():
    data = {"domain_name": "example.com"}
    assert SubdomainFinderInput(**data)


def test_subdomain_finder_output():
    data = {
        "domain_name": "example.com",
        "subdomains": ["www.example.com", "api.example.com"],
    }
    assert SubdomainFinderOutput(**data)


# --- Template Tool Schemas --- #


def test_template_input():
    data = {"parameter": "value", "result": "res", "error": None}
    assert TemplateToolInput(**data)


def test_template_output():
    data = {"result": "result"}
    assert TemplateToolOutput(**data)


# --- Tool Schemas --- #


def test_ip_lookup_input():
    """Test IPLookupInput schema."""
    data = {"ip_address": "1.1.1.1"}
    assert IPLookupInput(**data)
    data_ipv6 = {"ip_address": "::1"}
    assert IPLookupInput(**data_ipv6)


def test_ip_lookup_output():
    """Test IPLookupOutput schema."""
    data = {
        "ip_address": "1.1.1.1",
        "reputation": "benign",
        "details": {"source": "test"},
    }
    assert IPLookupOutput(**data)


# --- VirusTotal Schemas --- #


def test_virustotal_input():
    """Test VirusTotalInput schema."""
    data_domain = {"resource": "google.com", "resource_type": "domain"}
    data_ip = {"resource": "8.8.8.8", "resource_type": "ip"}
    assert VirusTotalInput(**data_domain)
    assert VirusTotalInput(**data_ip)


def test_virustotal_output():
    """Test VirusTotalOutput schema."""
    data = {
        "resource": "google.com",
        "analysis_link": "http://vt.com/123",
        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
    }
    assert VirusTotalOutput(**data)


# --- Whois Lookup Schemas --- #


def test_whois_input():
    data = {"domain": "google.com"}
    assert WhoisLookupInput(**data)


def test_whois_output():
    data = {
        "raw_text": "Domain: google.com...",
        "parsed_data": {"registrar": "MarkMonitor"},
    }
    data = {
        "domain_name": "google.com",
        "registrar": "MarkMonitor Inc.",
        "raw_data": "...",
    }
    assert WhoisLookupOutput(**data)


# --- Example Validation Failure Test --- #


def test_whois_input_validation_failure():
    # Test with None for required field should fail
    with pytest.raises(ValidationError):
        WhoisLookupInput(domain=None)  # None should fail for required field
    # Test with missing field should fail
    with pytest.raises(ValidationError):
        WhoisLookupInput()  # Missing required field
