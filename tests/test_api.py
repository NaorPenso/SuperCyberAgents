"""Tests for the API endpoints."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


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
