from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import dns.exception
import dns.resolver
import socket # Import socket for gaierror

# Add shodan mock
import shodan

# Import ipwhois and its exceptions
from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError, IPDefinedError, WhoisRateLimitError

from tools.domain_tools import (
    _query_dns,
    crt_sh_lookup,
    email_security_check,
    ipwhois_lookup, # Import the tool
    shodan_host_lookup,  # Import new tool
    virustotal_url_analysis,  # Import new tool
)

# --- Fixtures ---

# Sample data for mocking
MOCK_DOMAIN = "example.com"
MOCK_IP = "93.184.216.34"

MOCK_WHOIS_RESULT = {
    "asn": "15133",
    "asn_cidr": "93.184.216.0/24",
    "asn_country_code": "US",
    "asn_description": "EDGECAST, US",
    "nets": [{"cidr": "93.184.216.0/24", "name": "EXAMPLE-NET"}],
}

MOCK_SHODAN_RESULT = {
    "ip_str": MOCK_IP,
    "org": "Test Org",
    "os": "Linux",
    "ports": [80, 443],
    "tags": ["web", "test"],
    "vulns": ["CVE-2023-1234"],
    "last_update": "2024-01-01T00:00:00.000000",
    "country_name": "Testland",
    "city": "Testville",
}

MOCK_VT_RESULT_FOUND = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 0,
                "harmless": 68,
                "undetected": 10,
            },
            "last_analysis_date": 1704067200,  # 2024-01-01T00:00:00Z
        }
    }
}

MOCK_VT_RESULT_NOT_FOUND = {  # Simulates VT API returning 404
    "error": {"message": "URL not found", "code": "NotFoundError"}
}

MOCK_CRTSH_RAW_DATA = [
    {
        "issuer_ca_id": 16418,
        "issuer_name": "C=US, O=Let\'s Encrypt, CN=Let\'s Encrypt Authority X3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "id": 1234567890,
        "entry_timestamp": "2023-01-01T10:00:00.123",
        "not_before": "2023-01-01T00:00:00",
        "not_after": "2024-04-01T00:00:00",
        "serial_number": "0a1b2c3d4e5f"
    },
    {
        "issuer_ca_id": 1426,
        "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert SHA2 High Assurance Server CA",
        "common_name": None, # Test case with None common_name
        "name_value": "test.example.com\n", # Test case with trailing newline
        "id": 9876543210,
        "entry_timestamp": "2022-12-01T11:00:00.456",
        "not_before": "2022-12-01T00:00:00",
        "not_after": "2023-12-01T00:00:00",
        "serial_number": "f5e4d3c2b1a0"
    }
]

@pytest.mark.asyncio
@patch("asyncio.to_thread")
async def test_query_dns_success(mock_to_thread):
    """Test _query_dns successful resolution."""
    # Mock the return value of the underlying dns.resolver.resolve call
    mock_answer = MagicMock()
    # Mock the specific method call chain used in the list comprehension
    mock_answer.to_text.return_value.strip.return_value = "192.0.2.1"
    mock_to_thread.return_value = [mock_answer]

    result = await _query_dns("example.com", "A")

    assert result == ["192.0.2.1"]
    mock_to_thread.assert_awaited_once()


@pytest.mark.asyncio
@patch("asyncio.to_thread")
async def test_query_dns_nxdomain(mock_to_thread, caplog):
    """Test _query_dns handling NXDOMAIN."""
    mock_to_thread.side_effect = dns.resolver.NXDOMAIN

    result = await _query_dns("nxdomain.com", "A")

    assert result == [] # Should return empty list on NXDOMAIN
    mock_to_thread.assert_awaited_once()
    assert "Domain nxdomain.com does not exist (NXDOMAIN)." in caplog.text
    # Check log level (optional but good practice)
    assert caplog.records[-1].levelname == "WARNING"


@pytest.mark.asyncio
@patch("asyncio.to_thread")
async def test_query_dns_noanswer(mock_to_thread, caplog):
    """Test _query_dns handling NoAnswer."""
    mock_to_thread.side_effect = dns.resolver.NoAnswer

    result = await _query_dns("noanswer.com", "MX")

    assert result == [] # Should return empty list on NoAnswer
    mock_to_thread.assert_awaited_once()
    # Check the exact log message and level
    assert "No MX record found for noanswer.com" in caplog.text
    assert caplog.records[-1].levelname == "DEBUG"


@pytest.mark.asyncio
@patch("asyncio.to_thread")
async def test_query_dns_timeout(mock_to_thread, caplog):
    """Test _query_dns handling Timeout."""
    mock_to_thread.side_effect = dns.exception.Timeout

    result = await _query_dns("timeout.com", "A")

    assert result == [] # Should return empty list on Timeout
    mock_to_thread.assert_awaited_once()
    assert "DNS query timeout for A at timeout.com" in caplog.text
    assert caplog.records[-1].levelname == "ERROR"


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_error(mock_query_dns):
    mock_query_dns.side_effect = Exception("DNS query failed unexpectedly")
    result = await email_security_check(MOCK_DOMAIN)
    # Should return the partially filled/default dict even on error
    assert result["spf_record"] is None
    assert result["dmarc_record"] is None


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_nxdomain(mock_query_dns, caplog):
    """Test email_security_check when DNS query returns NXDOMAIN."""
    mock_query_dns.side_effect = dns.resolver.NXDOMAIN
    result = await email_security_check(MOCK_DOMAIN)
    # Should return default dictionary
    assert result["spf_record"] is None
    assert result["dmarc_record"] is None
    # Check for logs from the calling function (email_security_check/_check_spf/_check_dmarc)
    assert "Error checking SPF for example.com" in caplog.text
    assert "Error checking DMARC for example.com" in caplog.text


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_noanswer(mock_query_dns, caplog):
    """Test email_security_check when DNS query returns NoAnswer."""
    # Make the first call (SPF) return NoAnswer, second (DMARC) succeed (empty list)
    mock_query_dns.side_effect = [dns.resolver.NoAnswer, []]
    result = await email_security_check(MOCK_DOMAIN)
    # SPF should be None, DMARC should be None (as record list is empty)
    assert result["spf_record"] is None
    assert result["dmarc_record"] is None
    # Check for logs from the calling function
    assert "Error checking SPF for example.com" in caplog.text
    assert "No DMARC record found for example.com" in caplog.text # This is logged when DMARC lookup is empty
    # Check that DMARC query was also attempted
    assert mock_query_dns.call_count == 2
    assert mock_query_dns.call_args_list[1][0][0] == f"_dmarc.{MOCK_DOMAIN}"


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
@pytest.mark.parametrize(
    "dmarc_record_content, expected_policy",
    [
        (["v=DMARC1; p=reject;"], "reject"),
        (["v=DMARC1; p=quarantine;"], "quarantine"),
        (["v=DMARC1; p=none;"], "none"),
        (["v=DMARC1;"], None), # No policy specified
        ([], None), # No record found
    ]
)
async def test_email_security_check_dmarc_policies(mock_query_dns, dmarc_record_content, expected_policy):
    """Test email_security_check correctly parses various DMARC policies."""
    # Mock SPF lookup (return no record), mock DMARC lookup with parametrized content
    mock_query_dns.side_effect = [[], dmarc_record_content]

    result = await email_security_check(MOCK_DOMAIN)

    # SPF part should be None
    assert result["spf_record"] is None

    # DMARC part should match expectations
    if dmarc_record_content:
        assert result["dmarc_record"] == dmarc_record_content[0]
        assert result["dmarc_valid"] is True
    else:
        assert result["dmarc_record"] is None
        assert result["dmarc_valid"] is None

    assert result["dmarc_policy"] == expected_policy
    assert mock_query_dns.call_count == 2


# --- Tests for shodan_host_lookup ---


@pytest.mark.asyncio
@patch("os.getenv")
@patch("asyncio.to_thread")
@patch("shodan.Shodan")
async def test_shodan_host_lookup_success(mock_shodan_cls, mock_to_thread, mock_getenv):
    mock_getenv.return_value = "FAKE_SHODAN_KEY"  # Simulate API key present
    mock_shodan_instance = MagicMock()
    mock_shodan_cls.return_value = mock_shodan_instance
    mock_to_thread.return_value = MOCK_SHODAN_RESULT

    result = await shodan_host_lookup(MOCK_IP)

    assert result is not None
    assert result["ip_address"] == MOCK_IP
    assert result["organization"] == "Test Org"
    assert result["os"] == "Linux"
    assert result["ports"] == [80, 443]
    assert result["vulns"] == ["CVE-2023-1234"]

    mock_getenv.assert_called_with("SHODAN_API_KEY")
    mock_shodan_cls.assert_called_once_with("FAKE_SHODAN_KEY")
    mock_to_thread.assert_awaited_once_with(mock_shodan_instance.host, MOCK_IP)


@pytest.mark.asyncio
@patch("os.getenv")
async def test_shodan_host_lookup_no_api_key(mock_getenv):
    mock_getenv.return_value = None  # Simulate API key missing
    result = await shodan_host_lookup(MOCK_IP)
    assert result is None
    mock_getenv.assert_called_with("SHODAN_API_KEY")


@pytest.mark.asyncio
@patch("os.getenv")
@patch("asyncio.to_thread")
@patch("shodan.Shodan")
async def test_shodan_host_lookup_api_error_not_found(
    mock_shodan_cls, mock_to_thread, mock_getenv
):
    mock_getenv.return_value = "FAKE_SHODAN_KEY"
    mock_shodan_instance = MagicMock()
    mock_shodan_cls.return_value = mock_shodan_instance
    mock_to_thread.side_effect = shodan.APIError(
        "No information available for that IP."
    )

    result = await shodan_host_lookup(MOCK_IP)
    # Should return minimal dict when IP not found
    assert result == {"ip_address": MOCK_IP}


@pytest.mark.asyncio
@patch("os.getenv")
@patch("asyncio.to_thread")
@patch("shodan.Shodan")
async def test_shodan_host_lookup_api_error_other(
    mock_shodan_cls, mock_to_thread, mock_getenv
):
    mock_getenv.return_value = "FAKE_SHODAN_KEY"
    mock_shodan_instance = MagicMock()
    mock_shodan_cls.return_value = mock_shodan_instance
    mock_to_thread.side_effect = shodan.APIError("Invalid API key.")

    result = await shodan_host_lookup(MOCK_IP)
    assert result is None  # Other API errors return None


# --- Tests for virustotal_url_analysis ---


@pytest.mark.asyncio
@patch("os.getenv")
@patch("httpx.AsyncClient")
async def test_virustotal_url_analysis_success(mock_client_cls, mock_getenv):
    mock_getenv.return_value = "FAKE_VT_KEY"

    # 1. Create the mock response
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_VT_RESULT_FOUND
    mock_response.raise_for_status = MagicMock() # No error for success case

    # 2. Create the mock AsyncClient *instance*
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response

    # 3. Configure the mocked AsyncClient *class* to return the instance
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    # Run the tool function
    result = await virustotal_url_analysis(MOCK_DOMAIN)

    # Assertions
    assert result is not None
    assert result["url"] == f"http://{MOCK_DOMAIN}"
    assert result["malicious_count"] == 2
    assert result["harmless_count"] == 68
    assert result["last_analysis_date"] == "2024-01-01T00:00:00+00:00"
    mock_getenv.assert_called_with("VIRUSTOTAL_API_KEY")
    mock_client_instance.get.assert_awaited_once() # Check call on the instance


@pytest.mark.asyncio
@patch("os.getenv")
async def test_virustotal_url_analysis_no_api_key(mock_getenv):
    mock_getenv.return_value = None
    result = await virustotal_url_analysis(MOCK_DOMAIN)
    assert result is None


@pytest.mark.asyncio
@patch("os.getenv")
@patch("httpx.AsyncClient")
async def test_virustotal_url_analysis_not_found(mock_client_cls, mock_getenv):
    mock_getenv.return_value = "FAKE_VT_KEY"

    # 1. Mock response for 404
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404
    mock_http_error = httpx.HTTPStatusError(
        "Not Found", request=MagicMock(), response=mock_response
    )
    # Don't mock json() for 404
    mock_response.raise_for_status = MagicMock(side_effect=mock_http_error)

    # 2. Create mock client instance
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response # get() returns the 404 response

    # 3. Configure class mock
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    # Run
    result = await virustotal_url_analysis(MOCK_DOMAIN)

    # Assertions
    # Should return minimal dict when URL not found
    assert result == {"url": f"http://{MOCK_DOMAIN}"}
    mock_client_instance.get.assert_awaited_once()


@pytest.mark.asyncio
@patch("os.getenv")
@patch("httpx.AsyncClient")
async def test_virustotal_url_analysis_http_error(mock_client_cls, mock_getenv):
    mock_getenv.return_value = "FAKE_VT_KEY"

    # 1. Mock response for 500
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 500
    mock_http_error = httpx.HTTPStatusError(
        "Server Error", request=MagicMock(), response=mock_response
    )
    mock_response.raise_for_status = MagicMock(side_effect=mock_http_error)

    # 2. Create mock client instance
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response

    # 3. Configure class mock
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    # Run
    result = await virustotal_url_analysis(MOCK_DOMAIN)

    # Assertions
    assert result is None
    mock_client_instance.get.assert_awaited_once()


@pytest.mark.asyncio
@patch("os.getenv")
@patch("httpx.AsyncClient")
async def test_virustotal_url_analysis_network_error(mock_client_cls, mock_getenv):
    mock_getenv.return_value = "FAKE_VT_KEY"

    # 1. Create mock client instance that raises RequestError on get()
    mock_client_instance = AsyncMock()
    mock_client_instance.get.side_effect = httpx.RequestError(
        "Timeout", request=MagicMock()
    )

    # 2. Configure class mock
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    # Run
    result = await virustotal_url_analysis(MOCK_DOMAIN)

    # Assertions
    assert result is None
    mock_client_instance.get.assert_awaited_once()


# --- Tests for crt_sh_lookup ---

@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_crt_sh_lookup_success(mock_client_cls):
    """Test crt_sh_lookup successfully parsing data."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_CRTSH_RAW_DATA
    mock_response.raise_for_status = MagicMock()

    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    result = await crt_sh_lookup(MOCK_DOMAIN)

    assert len(result) == 2
    # Check first certificate parsing and cleaning
    assert result[0]["issuer_name"] == "C=US, O=Let\'s Encrypt, CN=Let\'s Encrypt Authority X3"
    assert result[0]["common_names"] == sorted(["example.com", "www.example.com"])
    assert result[0]["not_before"] == "2023-01-01T00:00:00"
    assert result[0]["not_after"] == "2024-04-01T00:00:00"
    assert result[0]["serial_number"] == "0a1b2c3d4e5f"
    # Check second certificate parsing and cleaning (handles None common_name, extra newline)
    assert result[1]["issuer_name"] == "C=US, O=DigiCert Inc, CN=DigiCert SHA2 High Assurance Server CA"
    assert result[1]["common_names"] == ["test.example.com"]
    assert result[1]["serial_number"] == "f5e4d3c2b1a0"

    mock_client_instance.get.assert_awaited_once_with(
        f"https://crt.sh/?q={MOCK_DOMAIN}&output=json", timeout=30.0
    )

@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_crt_sh_lookup_http_error(mock_client_cls, caplog):
    """Test crt_sh_lookup handling HTTPStatusError."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 500
    mock_response.request = MagicMock()
    mock_response.request.url = f"https://crt.sh/?q={MOCK_DOMAIN}&output=json"
    mock_http_error = httpx.HTTPStatusError(
        "Server Error", request=mock_response.request, response=mock_response
    )
    mock_response.raise_for_status = MagicMock(side_effect=mock_http_error)

    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    result = await crt_sh_lookup(MOCK_DOMAIN)

    assert result == []
    assert f"HTTP error fetching crt.sh data for {MOCK_DOMAIN}" in caplog.text

@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_crt_sh_lookup_request_error(mock_client_cls, caplog):
    """Test crt_sh_lookup handling RequestError."""
    mock_client_instance = AsyncMock()
    mock_client_instance.get.side_effect = httpx.RequestError("Network error", request=MagicMock())
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    result = await crt_sh_lookup(MOCK_DOMAIN)

    assert result == []
    assert f"Network error fetching crt.sh data for {MOCK_DOMAIN}" in caplog.text

@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_crt_sh_lookup_generic_exception(mock_client_cls, caplog):
    """Test crt_sh_lookup handling generic Exception during processing."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    # Make json() raise an error
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_response.raise_for_status = MagicMock()

    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    result = await crt_sh_lookup(MOCK_DOMAIN)

    assert result == []
    assert f"Error processing crt.sh data for {MOCK_DOMAIN}" in caplog.text

@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_crt_sh_lookup_unexpected_data_format(mock_client_cls, caplog):
    """Test crt_sh_lookup handling unexpected (non-list) data format."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"error": "some error format"} # Return dict, not list
    mock_response.raise_for_status = MagicMock()

    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_cls.return_value.__aenter__.return_value = mock_client_instance

    result = await crt_sh_lookup(MOCK_DOMAIN)

    assert result == []
    assert f"crt.sh returned unexpected data format for {MOCK_DOMAIN}" in caplog.text

# --- Tests for ipwhois_lookup ---

@pytest.mark.asyncio
@patch("asyncio.get_running_loop") # Patch the loop first
@patch("asyncio.to_thread") # Then patch to_thread
@patch("tools.domain_tools.IPWhois") # Patch IPWhois class used inside
async def test_ipwhois_lookup_success(mock_ipwhois_cls, mock_to_thread, mock_get_loop):
    """Test ipwhois_lookup success path."""
    # Mock loop and getaddrinfo
    mock_loop = AsyncMock()
    mock_get_loop.return_value = mock_loop
    # Simulate getaddrinfo returning a valid IP
    # Structure: [(family, type, proto, canonname, sockaddr)]
    mock_loop.getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (MOCK_IP, 0))
    ]

    # Mock IPWhois instance and lookup_whois call via to_thread
    mock_ipwhois_instance = MagicMock()
    mock_ipwhois_cls.return_value = mock_ipwhois_instance
    mock_to_thread.return_value = MOCK_WHOIS_RESULT # Simulate successful lookup

    result = await ipwhois_lookup(MOCK_DOMAIN)

    assert result is not None
    assert result["ip_address"] == MOCK_IP
    assert result["asn"] == "15133"
    assert result["asn_description"] == "EDGECAST, US"

    mock_get_loop.assert_called_once()
    mock_loop.getaddrinfo.assert_awaited_once_with(MOCK_DOMAIN, None, family=socket.AF_INET)
    mock_ipwhois_cls.assert_called_once_with(MOCK_IP)
    # Check that obj.lookup_whois was the function passed to to_thread
    assert mock_to_thread.call_args[0][0] == mock_ipwhois_instance.lookup_whois

@pytest.mark.asyncio
@patch("asyncio.get_running_loop")
async def test_ipwhois_lookup_resolution_gaierror(mock_get_loop, caplog):
    """Test ipwhois_lookup when domain resolution fails (gaierror)."""
    mock_loop = AsyncMock()
    mock_get_loop.return_value = mock_loop
    mock_loop.getaddrinfo.side_effect = socket.gaierror("Test gaierror")

    result = await ipwhois_lookup(MOCK_DOMAIN)

    assert result is None
    assert f"Could not resolve domain {MOCK_DOMAIN}" in caplog.text
    mock_loop.getaddrinfo.assert_awaited_once()

@pytest.mark.asyncio
@patch("asyncio.get_running_loop")
async def test_ipwhois_lookup_resolution_exception(mock_get_loop, caplog):
    """Test ipwhois_lookup when domain resolution raises generic Exception."""
    mock_loop = AsyncMock()
    mock_get_loop.return_value = mock_loop
    mock_loop.getaddrinfo.side_effect = Exception("Generic resolution error")

    result = await ipwhois_lookup(MOCK_DOMAIN)

    assert result is None
    assert f"Unexpected error during domain resolution for {MOCK_DOMAIN}" in caplog.text
    mock_loop.getaddrinfo.assert_awaited_once()

@pytest.mark.asyncio
@patch("asyncio.get_running_loop")
@patch("asyncio.to_thread")
@patch("tools.domain_tools.IPWhois")
@pytest.mark.parametrize(
    "ipwhois_exception",
    [
        ASNRegistryError("Test ASN Error"),
        IPDefinedError("Test IP Defined Error"),
        WhoisRateLimitError("Test Rate Limit"),
        Exception("Generic WHOIS error"), # Test generic exception during lookup
    ]
)
async def test_ipwhois_lookup_whois_exceptions(
    mock_ipwhois_cls, mock_to_thread, mock_get_loop, ipwhois_exception, caplog
):
    """Test ipwhois_lookup handling various exceptions during the whois lookup phase."""
    # Mock resolution success
    mock_loop = AsyncMock()
    mock_get_loop.return_value = mock_loop
    mock_loop.getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (MOCK_IP, 0))
    ]

    # Mock IPWhois instance and make lookup_whois raise the parametrized exception
    mock_ipwhois_instance = MagicMock()
    mock_ipwhois_cls.return_value = mock_ipwhois_instance
    mock_to_thread.side_effect = ipwhois_exception

    result = await ipwhois_lookup(MOCK_DOMAIN)

    assert result is None
    if isinstance(ipwhois_exception, (ASNRegistryError, IPDefinedError, WhoisRateLimitError)):
        assert f"IP Whois lookup failed for {MOCK_IP}" in caplog.text
    else:
        assert f"Error during IP Whois lookup for {MOCK_IP}" in caplog.text
    mock_to_thread.assert_awaited_once()

# --- Tests for email_security_check --- #


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_success(mock_query_dns):
    """Test email_security_check successful lookup."""
    mock_query_dns.side_effect = [
        ["v=spf1 include:_spf.google.com ~all"],  # SPF result
        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"], # DMARC result
    ]
    result = await email_security_check(MOCK_DOMAIN)
    assert result["spf_record"] == "v=spf1 include:_spf.google.com ~all"
    assert result["spf_valid"] is True
    assert result["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    assert result["dmarc_valid"] is True
    assert result["dmarc_policy"] == "reject"
    assert mock_query_dns.call_count == 2


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_generic_exception(mock_query_dns, caplog):
    """Test email_security_check when _query_dns raises generic Exception."""
    mock_query_dns.side_effect = Exception("Generic DNS error")
    result = await email_security_check(MOCK_DOMAIN)
    # Even with exceptions, it should return the default structure
    assert result["spf_record"] is None
    assert result["spf_valid"] is None
    assert result["dmarc_record"] is None
    assert result["dmarc_policy"] is None
    assert result["dmarc_valid"] is None
    # Check logs from the helper functions' except blocks
    assert f"Error checking SPF for {MOCK_DOMAIN}: Generic DNS error" in caplog.text
    assert f"Error checking DMARC for {MOCK_DOMAIN}: Generic DNS error" in caplog.text
    assert mock_query_dns.call_count == 2 # Ensure both SPF and DMARC were attempted


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_no_records(mock_query_dns):
    """Test email_security_check when no SPF or DMARC records are found."""
    mock_query_dns.return_value = [] # Simulate no records found