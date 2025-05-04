"""Global fixtures for pytest."""

import pytest


@pytest.fixture
def mock_domain_info():
    """Return mock domain information for testing across different modules."""
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
