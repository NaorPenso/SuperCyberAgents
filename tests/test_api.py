"""Tests for the FastAPI application endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient

# Assuming your FastAPI app instance is named 'app' in 'api.main'
from api.main import app

client = TestClient(app)


def test_read_root():
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "SuperCyberAgents API is running"}


def test_health_check():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_agents_root():
    """Test the root endpoint for the agents router."""
    response = client.get("/agents/")
    assert response.status_code == 200
    assert response.json() == {"message": "Agent router is active"}


# --- Test Lifespan --- #


@patch("api.main.initialize_system")
@patch("api.main.setup_logging")
def test_lifespan_startup(mock_setup_logging, mock_initialize_system):
    """Test that initialization and logging setup are called during startup."""
    # The TestClient context manager triggers the lifespan events
    with TestClient(app) as tc:
        # Make a dummy request to ensure the app starts fully if needed, though
        # the context manager itself should trigger startup.
        tc.get("/health")

    mock_setup_logging.assert_called()
    mock_initialize_system.assert_called_once()


# Note: Testing shutdown logging is harder with TestClient as it happens
# after the context manager exits. Testing startup calls is generally sufficient.
