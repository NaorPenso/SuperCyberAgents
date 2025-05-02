from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# Add shodan mock
import shodan

from tools.domain_tools import (
    email_security_check,
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


@pytest.mark.asyncio
@patch("tools.domain_tools._query_dns")
async def test_email_security_check_error(mock_query_dns):
    mock_query_dns.side_effect = Exception("DNS query failed unexpectedly")
    result = await email_security_check(MOCK_DOMAIN)
    # Should return the partially filled/default dict even on error
    assert result["spf_record"] is None
    assert result["dmarc_record"] is None


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
    assert result["last_analysis_date"] == "2024-01-01T00:00:00Z"
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
