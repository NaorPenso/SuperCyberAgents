"""Integration tests for the FastAPI application."""

from typing import ClassVar, List

import pytest
from fastapi.testclient import TestClient


# Define the app fixture to ensure lifespan events run
# Requires pytest-asyncio
@pytest.fixture(scope="module")
def test_app_fixture():
    # Import here to avoid loading modules before mocks might be needed elsewhere
    from api.main import app

    # If lifespan needs async context, adjust fixture scope or setup
    with TestClient(app) as client:
        yield client


# --- Mocking Setup ---
@pytest.fixture(autouse=True)
def mock_system_initialization(monkeypatch):
    """Mock the core initialization to avoid actual loading in API tests."""

    # Mock get_agent and get_all_agents to return controlled data
    class MockAgentConfig:
        id = "mock-agent"
        description = "Mock Agent"
        llm_provider = "mock_provider"
        model = "mock_model"
        input_schema = "MockInputSchema"
        output_schema = "MockOutputSchema"
        tools: ClassVar[List[str]] = []

    class MockOutput:
        def model_dump(self):
            return {"result": "mock success"}

    class MockAgent:
        config = MockAgentConfig()
        input_schema = None  # Will be mocked inside endpoint test

        def run(self, input_data):
            if input_data.get("fail"):  # Example trigger for failure
                raise ValueError("Simulated agent failure")
            return MockOutput()

    mock_agents = {"mock-agent": MockAgent()}

    monkeypatch.setattr("core.initialization.initialize_system", lambda: None)
    monkeypatch.setattr("core.initialization.get_agent", mock_agents.get)
    monkeypatch.setattr("core.initialization.get_all_agents", lambda: mock_agents)

    # Mock schema lookup
    class MockInputSchema:
        def __init__(self, **kwargs):
            self.data = kwargs
            if "invalid" in kwargs:
                raise ValueError("Invalid input schema")

        def get(self, key):
            return self.data.get(key)

    monkeypatch.setattr(
        "api.routers.agents._get_schema_class",
        lambda name: MockInputSchema if name == "MockInputSchema" else None,
    )


# --- Tests --- #
def test_health_check(test_app_fixture):
    """Test the /health endpoint."""
    response = test_app_fixture.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_agents(test_app_fixture):
    """Test the GET /agents/ endpoint."""
    response = test_app_fixture.get("/agents/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["id"] == "mock-agent"
    assert data[0]["input_schema_name"] == "MockInputSchema"


def test_invoke_agent_success(test_app_fixture):
    """Test POST /agents/{agent_id}/invoke successfully."""
    agent_id = "mock-agent"
    input_payload = {"input": {"data": "some input"}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == agent_id
    assert data["output"] == {"result": "mock success"}


def test_invoke_agent_not_found(test_app_fixture):
    """Test invoking a non-existent agent."""
    agent_id = "non-existent-agent"
    input_payload = {"input": {"data": "test"}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_invoke_agent_invalid_input(test_app_fixture):
    """Test invoking an agent with data failing schema validation."""
    agent_id = "mock-agent"
    # The mocked schema validator raises ValueError if 'invalid' key exists
    input_payload = {"input": {"invalid": True}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)

    assert response.status_code == 400
    assert "Invalid input data" in response.json()["detail"]


def test_invoke_agent_execution_error(test_app_fixture):
    """Test invoking an agent that raises an exception during run."""
    agent_id = "mock-agent"
    # The mocked agent run method raises ValueError if 'fail' key exists
    input_payload = {"input": {"fail": True}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)

    assert response.status_code == 500
    assert "Agent execution failed" in response.json()["detail"]
    assert "Simulated agent failure" in response.json()["detail"]


def test_invoke_agent_schema_not_found(test_app_fixture, monkeypatch):
    """Test invoking an agent whose schema cannot be found."""
    # Override the schema lookup mock for this test
    monkeypatch.setattr("api.routers.agents._get_schema_class", lambda name: None)

    agent_id = "mock-agent"
    input_payload = {"input": {"data": "test"}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)

    assert response.status_code == 500
    assert "Agent input schema configuration error" in response.json()["detail"]
