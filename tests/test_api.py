"""Integration tests for the FastAPI application."""

# Removed ClassVar, MagicMock, BaseModel imports specific to old mocks
from starlette.testclient import TestClient

# BaseAgent not needed directly
# api.main.app is imported within the fixture in conftest

# --- Removed Old Mock Data/Classes ---
# MockAgentConfig, MockInputSchema, MockOutputSchema removed.

# --- Removed Old Fixture ---
# Local test_app_fixture removed. Using the one from conftest.py

# --- Test Cases ---

# Keep test_tool_config_validation if it tests a valid schema structure directly
# def test_tool_config_validation():
#     # ... existing test ...
#     pass


# Test Health Check - Uses test_app_fixture from conftest
def test_health_check(test_app_fixture: TestClient):
    """Test the /health endpoint."""
    response = test_app_fixture.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# Test List Agents - Uses test_app_fixture from conftest
def test_list_agents(test_app_fixture: TestClient):
    """Test the GET /agents/ endpoint.

    Relies on get_all_agents patched by mock_system_state in conftest.py
    """
    response = test_app_fixture.get("/agents/")
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)
    # Check for agents instantiated in conftest:mock_system_state
    agent_ids = [agent["id"] for agent in agents]
    assert "security_manager" in agent_ids
    assert "domain_whois_agent" in agent_ids
    # Optional: Check descriptions or other fields if reliable
    # sec_mgr_data = next(a for a in agents if a['id'] == "security_manager")
    # assert sec_mgr_data['description'] == "Security Manager Agent Description..."


# Test Agent Invoke Success - Uses test_app_fixture from conftest
# Note: API tests typically don't inject agent override fixtures directly.
# The fixture in conftest provides the base TestClient.
# The underlying agent instance obtained via get_agent IS the real one,
# but we rely on tests for agent *units* (like test_agents.py) to use overrides.
# For API tests, we check if the route works and returns *something*.
# The exact output depends on whether the mocked state includes overrides,
# which our current conftest doesn't do globally for API calls.
# Let's assume basic TestModel behavior (JSON summary) for now.
def test_invoke_agent_success(test_app_fixture: TestClient):
    """Test POST /agents/{agent_id}/invoke successfully (basic check)."""
    agent_id = "security_manager"  # Use a real agent ID from mocked state
    # Payload matches the actual SecurityManagerInput schema
    input_payload = {"input": {"task_description": "API test task"}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)
    assert response.status_code == 200
    response_data = response.json()

    # Check InvokeResponse structure
    assert "agent_id" in response_data
    assert response_data["agent_id"] == agent_id
    assert "output" in response_data

    # Check agent output data inside the output field
    output_data = response_data["output"]
    assert "status" in output_data
    assert output_data["status"] == "success"


# Test Agent Invoke Invalid Input - Uses test_app_fixture from conftest
def test_invoke_agent_invalid_input(test_app_fixture: TestClient):
    """Test invoking an agent with data failing its actual schema validation."""
    agent_id = "security_manager"
    # Input missing required 'task_description' field for SecurityManagerInput
    input_payload = {"input": {"wrong_field": True}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)
    assert response.status_code == 400  # API returns 400 for validation errors
    # Check for Pydantic validation error details
    assert "detail" in response.json()
    assert isinstance(response.json()["detail"], str)  # Error is serialized as string


# Test Agent Invoke Execution Error - Commented out
# Hard to reliably trigger specific agent execution errors via API
# without complex mocking or FunctionModel within the API test scope.
# Better handled in agent unit tests.
# def test_invoke_agent_execution_error(test_app_fixture: TestClient):
#     """Test invoking an agent that raises an exception during run."""
#     pass

# Test Agent Invoke Schema Not Found - Commented out
# This tested internal router logic (_get_schema_class) which is removed/changed.
# The primary failure mode now would be AgentNotFoundError or Pydantic validation.
# def test_invoke_agent_schema_not_found(test_app_fixture: TestClient):
#    """Test invoking an agent whose input schema cannot be found."""
#    pass


# Test Agent Not Found - Uses test_app_fixture from conftest
def test_invoke_agent_not_found(test_app_fixture: TestClient):
    """Test invoking a non-existent agent.

    Relies on get_agent patched by mock_system_state raising AgentNotFoundError.
    """
    agent_id = "non-existent-agent"
    # Use a valid input structure even if agent doesn't exist, to avoid 422 error
    input_payload = {"input": {"task_description": "test"}}
    response = test_app_fixture.post(f"/agents/{agent_id}/invoke", json=input_payload)
    assert response.status_code == 404
    assert response.json()["detail"] == f"Agent '{agent_id}' not found"
