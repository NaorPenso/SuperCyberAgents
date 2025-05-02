"""Tests for the NetworkSecurityAgent.

This tests the NetworkSecurityAgent implementation, including its tools and functionality.
"""

import os
from datetime import datetime
from typing import List
from unittest.mock import patch

import pytest

from agents.network_security_agent import (
    NetworkScanResult,
    NetworkSecurityAgent,
    ScanSeverity,
    VulnerabilityFinding,
    network_security_agent,
)


# Test fixtures
@pytest.fixture
def sample_vulnerability_findings() -> List[VulnerabilityFinding]:
    """Return a list of sample vulnerability findings for testing."""
    return [
        VulnerabilityFinding(
            name="Cross-Site Scripting (XSS)",
            severity=ScanSeverity.HIGH,
            description="Reflected XSS vulnerability in the search function",
            remediation="Sanitize user input and implement Content-Security-Policy",
            references=["https://owasp.org/www-community/attacks/xss/"],
            cve_ids=["CVE-2021-1234"],
        ),
        VulnerabilityFinding(
            name="SQL Injection",
            severity=ScanSeverity.CRITICAL,
            description="SQL injection in login form",
            remediation="Use parameterized queries and ORM",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            cve_ids=["CVE-2022-5678"],
        ),
        VulnerabilityFinding(
            name="Information Disclosure",
            severity=ScanSeverity.LOW,
            description="Server version disclosed in HTTP headers",
            remediation="Configure server to not disclose version information",
            references=[],
            cve_ids=[],
        ),
    ]


@pytest.fixture
def sample_network_scan_result(sample_vulnerability_findings) -> NetworkScanResult:
    """Return a sample NetworkScanResult for testing."""
    return NetworkScanResult(
        target="example.com",
        scan_timestamp=datetime.now(),
        vulnerabilities=sample_vulnerability_findings,
        summary={
            "critical": 1,
            "high": 1,
            "low": 1,
            "total": 3,
        },
        scan_details={
            "scan_duration_seconds": 45,
            "templates_used": ["cves", "vulnerabilities"],
        },
        recommendations=[
            "Fix the critical SQL injection vulnerability in the login form immediately",
            "Address the high severity XSS vulnerability in the search function",
            "Consider updating server configuration to hide version information",
        ],
    )


@pytest.fixture
def mock_nuclei_result():
    """Return mock nuclei scan results."""
    return {
        "success": True,
        "findings": [
            {
                "template-id": "cves/2021/CVE-2021-1234",
                "template-path": "/nuclei-templates/cves/2021/CVE-2021-1234.yaml",
                "info": {
                    "name": "Cross-Site Scripting (XSS)",
                    "author": "test-author",
                    "severity": "high",
                    "description": "Reflected XSS vulnerability in the search function",
                    "reference": ["https://owasp.org/www-community/attacks/xss/"],
                    "classification": {
                        "cve-id": ["CVE-2021-1234"],
                        "cwe-id": ["CWE-79"],
                    },
                    "remediation": "Sanitize user input and implement Content-Security-Policy",
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/search?q=<script>alert(1)</script>",
                "timestamp": "2023-06-01T12:00:00+00:00",
            },
            {
                "template-id": "cves/2022/CVE-2022-5678",
                "template-path": "/nuclei-templates/cves/2022/CVE-2022-5678.yaml",
                "info": {
                    "name": "SQL Injection",
                    "author": "test-author",
                    "severity": "critical",
                    "description": "SQL injection in login form",
                    "reference": [
                        "https://owasp.org/www-community/attacks/SQL_Injection"
                    ],
                    "classification": {
                        "cve-id": ["CVE-2022-5678"],
                        "cwe-id": ["CWE-89"],
                    },
                    "remediation": "Use parameterized queries and ORM",
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/login",
                "timestamp": "2023-06-01T12:01:00+00:00",
            },
        ],
        "command": "nuclei -u example.com -json -o /tmp/nuclei_scan_example.com.json",
        "raw_output": "",
    }


@pytest.fixture
def mock_domain_info():
    """Return mock domain information."""
    return {
        "domain": "example.com",
        "subdomains": ["api.example.com", "www.example.com"],
        "ip_addresses": ["192.0.2.1", "192.0.2.2"],
        "dns_records": {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
        },
        "technologies": ["Nginx", "PHP", "jQuery"],
        "ssl_info": {
            "issuer": "Let's Encrypt",
            "expiry_date": "2023-12-31T23:59:59Z",
            "has_issues": False,
        },
        "security_headers": {
            "Content-Security-Policy": "missing",
            "X-XSS-Protection": "present",
            "X-Frame-Options": "present",
            "X-Content-Type-Options": "present",
        },
        "open_ports": [80, 443, 8080],
    }


# Set AGENT_ENV to 'test' to enable test mode for tools
@pytest.fixture(autouse=True)
def set_test_env():
    """Set the AGENT_ENV environment variable to 'test'."""
    old_env = os.environ.get("AGENT_ENV")
    os.environ["AGENT_ENV"] = "test"
    yield
    if old_env is not None:
        os.environ["AGENT_ENV"] = old_env
    else:
        del os.environ["AGENT_ENV"]


class TestNetworkSecurityAgent:
    """Tests for the NetworkSecurityAgent."""

    def test_agent_initialization(self):
        """Test that the agent initializes correctly."""
        agent = NetworkSecurityAgent()

        # Check that the agent has the right model
        assert "openai" in str(agent.model).lower()
        assert agent.output_type == NetworkScanResult

        # Ensure the singleton instance is properly initialized
        assert network_security_agent is not None
        assert isinstance(network_security_agent, NetworkSecurityAgent)

    @pytest.mark.asyncio
    async def test_scan_target_error_handling(self):
        """Test error handling in the scan_target method."""
        agent = NetworkSecurityAgent()

        # Create a mock run method that raises an exception
        async def mock_run(*args, **kwargs):
            raise Exception("Test error")

        # Apply the mock to the agent's run method
        with patch.object(agent, "run", side_effect=mock_run):
            # Call scan_target and expect a graceful error response
            result = await agent.scan_target(target="example.com")

            # Verify we get a valid result object with error information
            assert result.target == "example.com"
            assert "error" in result.summary
            assert "Test error" in result.scan_details["error"]
            assert "Scan failed" in result.recommendations[0]
