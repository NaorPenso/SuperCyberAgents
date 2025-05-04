"""Tests for the API endpoints."""

from datetime import datetime, timezone  # Import datetime and timezone
from unittest.mock import call, patch  # Import call

from fastapi.testclient import TestClient

from agents.network_security_agent import (  # Import necessary types
    NetworkScanResult,
    ScanSeverity,
)
from api.main import app
from schemas.domain_analysis import DomainAnalysisResult  # Import necessary types

client = TestClient(app, base_url="http://testserver")


def test_read_root():
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "SuperCyberAgents API is running"}


def test_agents_root():
    """Test the root endpoint for the agents router."""
    response = client.get("/agents/")
    assert response.status_code == 200
    expected_response = {
        "message": "Agent router is active",
        "available_agents": ["domain_analyzer_agent", "network_security_agent"],
    }
    assert response.json() == expected_response


def test_health_check():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# --- Tests for /agents/analyze-domain ---


@patch("api.routers.agents.run_domain_analysis")
def test_analyze_domain_success(mock_run_domain_analysis):
    """Test successful domain analysis via API."""
    mock_result_data = {
        "domain": "example.com",
        "analysis_summary": "Mocked success",
        "subdomains": ["www.example.com"],
        "certificates": [],
    }
    mock_run_domain_analysis.return_value = DomainAnalysisResult(**mock_result_data)

    request_data = {
        "domain": "example.com",
        "include_subdomains": True,
        "include_whois": False,
        "include_dns": False,
    }
    response = client.post("/agents/analyze-domain", json=request_data)

    assert response.status_code == 200
    # Validate against the Pydantic model returned
    result_obj = DomainAnalysisResult(**response.json())
    assert result_obj.domain == "example.com"
    assert result_obj.analysis_summary == "Mocked success"
    assert result_obj.certificates == []
    # Check the call on the patched standalone function (keyword argument)
    mock_run_domain_analysis.assert_called_once_with(domain_to_analyze="example.com")


@patch("api.routers.agents.run_domain_analysis")
def test_analyze_domain_error(mock_run_domain_analysis):
    """Test error during domain analysis via API."""
    mock_run_domain_analysis.side_effect = Exception("Agent run failed")

    request_data = {"domain": "error.com"}
    response = client.post("/agents/analyze-domain", json=request_data)

    assert response.status_code == 500
    assert "Error analyzing domain: Agent run failed" in response.json()["detail"]


# --- Tests for /agents/scan-target ---


@patch("api.routers.agents.scan_target")
@patch("api.routers.agents.run_domain_analysis")
def test_scan_target_success_with_domain_info(mock_run_domain_analysis, mock_scan_func):
    """Test successful target scan requesting and getting domain info."""
    mock_domain_dt = datetime.now(timezone.utc)
    mock_domain_result_data = {
        "domain": "domain.com",
        "analysis_id": "domain-abc",
        "timestamp": mock_domain_dt,
        "analysis_summary": "Domain OK",
        "ip_addresses": ["1.1.1.1"],
    }
    mock_run_domain_analysis.return_value = DomainAnalysisResult(
        **mock_domain_result_data
    )

    mock_scan_dt = datetime.now(timezone.utc)
    mock_scan_result = NetworkScanResult(
        target="http://domain.com",
        scan_timestamp=mock_scan_dt,
        vulnerabilities=[],
        summary={},
    )
    mock_scan_func.return_value = mock_scan_result

    request_data = {
        "target": "http://domain.com",
        "use_domain_info": True,
        "severity_filter": "high",
        "rate_limit": 100,
    }
    response = client.post("/agents/scan-target", json=request_data)

    assert response.status_code == 200
    assert response.json()["target"] == "http://domain.com"

    # Check call to domain analysis function (positional argument)
    mock_run_domain_analysis.assert_called_once_with("domain.com")

    # Construct the expected domain_info dict based on the mocked return value
    expected_domain_info = mock_run_domain_analysis.return_value.model_dump()

    # Check call to scan target function with the results from domain analysis
    mock_scan_func.assert_called_once_with(
        target="http://domain.com",
        domain_info=expected_domain_info,  # Use the dynamically created dict
        severity_filter=ScanSeverity.HIGH,
        rate_limit=100,
    )


@patch("api.routers.agents.scan_target")
@patch("api.routers.agents.run_domain_analysis")
def test_scan_target_success_domain_info_fails(
    mock_run_domain_analysis, mock_scan_func
):
    """Test successful target scan when requested domain info fails."""
    mock_run_domain_analysis.side_effect = Exception("Domain analysis failed")

    mock_scan_dt = datetime.now(timezone.utc)
    mock_scan_result = NetworkScanResult(
        target="http://domain.com",
        scan_timestamp=mock_scan_dt,
        vulnerabilities=[],
        summary={},
    )
    mock_scan_func.return_value = mock_scan_result

    request_data = {"target": "http://domain.com", "use_domain_info": True}
    response = client.post("/agents/scan-target", json=request_data)

    assert response.status_code == 200
    assert response.json()["target"] == "http://domain.com"
    mock_run_domain_analysis.assert_called_once_with("domain.com")
    mock_scan_func.assert_called_once_with(
        target="http://domain.com",
        domain_info=None,
        severity_filter=None,
        rate_limit=150,
    )


@patch("api.routers.agents.scan_target")
def test_scan_target_scan_error(mock_scan_func):
    """Test error during the network scan itself."""
    mock_scan_func.side_effect = Exception("Scan function failed")

    request_data = {"target": "fail.com", "use_domain_info": False}
    response = client.post("/agents/scan-target", json=request_data)

    assert response.status_code == 500
    assert "Error scanning target: Scan function failed" in response.json()["detail"]


# --- Test Lifespan Events (Basic) ---


@patch("api.main.initialize_system")
@patch("api.main.logger")
def test_lifespan_startup_shutdown(mock_api_logger, mock_init):
    """Simulate app startup and shutdown to cover lifespan logs."""
    # mock_logger_instance = MagicMock() # No longer need to mock getLogger
    # mock_get_logger.return_value = mock_logger_instance

    # Use the TestClient context manager to trigger lifespan events
    with TestClient(app) as test_client:
        # Startup assertions
        mock_init.assert_called_once()
        # Make a simple request to ensure app is running
        response = test_client.get("/health")
        assert response.status_code == 200

    # Check log calls using assert_has_calls with any_order=True
    # The actual logger is now patched, so check its calls directly
    expected_log_calls = [
        call.info("Starting up Cyber AI Agent API..."),
        call.info("Performing system initialization..."),
        call.info("System initialized successfully."),
        call.info("Shutting down Cyber AI Agent API..."),
    ]
    mock_api_logger.assert_has_calls(expected_log_calls, any_order=True)
