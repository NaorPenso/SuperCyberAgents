"""Shared fixtures for tests."""

import os
import sys
from unittest.mock import MagicMock, patch

import pydantic_ai.models  # Import the module directly
import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import HTTPException  # Moved import up
from fastapi.testclient import TestClient

# --- Project Imports (Moved Up) --- #
from agents.base import AgentConfig, ToolConfig
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent
from agents.security_manager.security_manager import SecurityManager
from schemas.delegate_task_schemas import DelegateTaskInput, DelegateTaskOutput
from schemas.domain_whois_schemas import DomainWhoisInput, DomainWhoisOutput
from schemas.registry import SCHEMA_REGISTRY
from schemas.security_manager_schemas import SecurityManagerInput, SecurityManagerOutput
from schemas.whois_lookup_schemas import WhoisLookupInput, WhoisLookupOutput
from tools.delegate_task_tool.delegate_task_tool import DelegateTaskTool
from tools.whois_lookup_tool.whois_lookup_tool import WhoisLookupTool

# --- End Project Imports --- #


# Add the project root to the Python path
# This MUST come AFTER standard library and third-party imports, but BEFORE project imports
# However, since the project imports need the path, we have a conflict.
# A common solution is to run pytest with PYTHONPATH set or use editable installs.
# For now, we keep it here and accept the E402s, or use noqa. Let's try keeping it here.
# We moved project imports above this line.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Disable actual LLM API calls during tests
# Set flag directly without using the non-existent function
pydantic_ai.models.ALLOW_MODEL_REQUESTS = False

# --- Removed Old Mocks ---
# MOCK_AGENT_CONFIG and MOCK_TOOL_CONFIG removed


# --- Global Mock for get_llm_client ---
@pytest.fixture(scope="session", autouse=True)
def mock_llm_client(monkeysession):
    """Mock get_llm_client globally to prevent real client initialization."""
    mock_provider = MagicMock()
    monkeysession.setattr(
        "core.llm_clients.get_llm_client", lambda provider_key: mock_provider
    )
    monkeysession.setattr(
        "agents.base.get_llm_client", lambda provider_key: mock_provider, raising=False
    )
    return mock_provider


# --- Create monkeysession fixture for session-scoped patches ---
@pytest.fixture(scope="session")
def monkeysession():
    """Create a session-scoped monkeypatch fixture."""
    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


# --- Mock Schema Registration (Minimal Example) ---
# In a real scenario, you might need more specific mock schemas
# or rely on the actual registry being populated if initialize_system mock handles it.
# For now, let's ensure the ones needed by agents exist minimally.
@pytest.fixture(scope="session", autouse=True)
def register_mock_schemas():
    # Ensure core schemas used by agents exist in the registry for tests
    if "SecurityManagerInput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["SecurityManagerInput"] = SecurityManagerInput
    if "SecurityManagerOutput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["SecurityManagerOutput"] = SecurityManagerOutput
    if "DomainWhoisInput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["DomainWhoisInput"] = DomainWhoisInput
    if "DomainWhoisOutput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["DomainWhoisOutput"] = DomainWhoisOutput
    if "WhoisLookupInput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["WhoisLookupInput"] = WhoisLookupInput
    if "WhoisLookupOutput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["WhoisLookupOutput"] = WhoisLookupOutput
    if "DelegateTaskInput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["DelegateTaskInput"] = DelegateTaskInput
    if "DelegateTaskOutput" not in SCHEMA_REGISTRY:
        SCHEMA_REGISTRY["DelegateTaskOutput"] = DelegateTaskOutput
    # Add others as needed


# --- Refactored System Mocking Fixture ---
@pytest.fixture(scope="function")
def mock_system_state(monkeypatch, register_mock_schemas):
    """Mocks system initialization to provide a state with REAL agent instances."""
    # Removed the problematic setattr for _load_providers

    # 2. Create a controlled state using a dictionary
    test_state = {
        "agents": {},  # Store agent configs IF needed by classes, else remove
        "tools": {},  # Store tool configs IF needed by classes, else remove
        "agent_instances": {},
        "tool_instances": {},
        "providers": {},
        "llm_clients": {},
        "system_initialized": True,  # Mark as initialized for tests
    }

    # 3. Define minimal mock configs needed for instantiation
    mock_delegate_tool_cfg = ToolConfig(
        name="delegate_task_tool",
        description="mock",
        input_schema="DelegateTaskInput",
        output_schema="DelegateTaskOutput",
    )
    mock_whois_tool_cfg = ToolConfig(
        name="whois_lookup_tool",
        description="mock",
        input_schema="WhoisLookupInput",
        output_schema="WhoisLookupOutput",
    )
    mock_sec_mgr_agent_cfg = AgentConfig(
        id="security_manager",
        name="Security Manager",
        description="mock",
        llm_provider="openai",
        model="mock",
        input_schema="SecurityManagerInput",
        output_schema="SecurityManagerOutput",
        tools=[],  # Empty list - we'll pass tool instances directly
    )
    mock_whois_agent_cfg = AgentConfig(
        id="domain_whois_agent",
        name="WHOIS Agent",
        description="mock",
        llm_provider="openai",
        model="mock",
        input_schema="DomainWhoisInput",
        output_schema="DomainWhoisOutput",
        tools=[],  # Empty list - we'll pass tool instances directly
    )

    # Store configs in state (optional, but helps keep track)
    test_state["tools"]["delegate_task_tool"] = mock_delegate_tool_cfg
    test_state["tools"]["whois_lookup_tool"] = mock_whois_tool_cfg
    test_state["agents"]["security_manager"] = mock_sec_mgr_agent_cfg
    test_state["agents"]["domain_whois_agent"] = mock_whois_agent_cfg

    # 4. Instantiate REAL tools needed by agents, passing mock config
    try:
        mock_delegate_tool = DelegateTaskTool(config=mock_delegate_tool_cfg)
        mock_whois_tool = WhoisLookupTool(config=mock_whois_tool_cfg)
        test_state["tool_instances"]["delegate_task_tool"] = mock_delegate_tool
        test_state["tool_instances"]["whois_lookup_tool"] = mock_whois_tool
    except Exception as e:
        pytest.fail(f"Failed to instantiate real tools for testing: {e}")

    # 5. Instantiate REAL agents, providing their necessary tool instances and mock config
    try:
        delegate_tool = test_state["tool_instances"]["delegate_task_tool"]
        whois_tool = test_state["tool_instances"]["whois_lookup_tool"]

        # Mock the LLM clients to prevent real client initialization
        with patch(
            "agents.security_manager.security_manager.get_llm_client",
            return_value=MagicMock(),
        ), patch(
            "agents.domain_whois_agent.domain_whois_agent.get_llm_client",
            return_value=MagicMock(),
        ):

            # Instantiate agents, passing required tools and mock config
            security_manager_instance = SecurityManager(
                config=mock_sec_mgr_agent_cfg, tools=[delegate_tool]
            )
            domain_whois_agent_instance = DomainWhoisAgent(
                config=mock_whois_agent_cfg, tools=[whois_tool]
            )

            # Add input_schema_class and output_schema_class attributes for CLI tests
            security_manager_instance.input_schema_class = SCHEMA_REGISTRY.get(
                "SecurityManagerInput"
            )
            security_manager_instance.output_schema_class = SCHEMA_REGISTRY.get(
                "SecurityManagerOutput"
            )
            domain_whois_agent_instance.input_schema_class = SCHEMA_REGISTRY.get(
                "DomainWhoisInput"
            )
            domain_whois_agent_instance.output_schema_class = SCHEMA_REGISTRY.get(
                "DomainWhoisOutput"
            )

        test_state["agent_instances"]["security_manager"] = security_manager_instance
        test_state["agent_instances"][
            "domain_whois_agent"
        ] = domain_whois_agent_instance

    except Exception as e:
        pytest.fail(f"Failed to instantiate real agents for testing: {e}")

    # 6. Mock initialize_system to return our controlled state dict
    monkeypatch.setattr("core.initialization.initialize_system", lambda: test_state)

    # 7. Patch get_agent functions to use the test state dict
    def mock_get_agent_api(agent_id: str):
        instance = test_state["agent_instances"].get(agent_id)
        if not instance:
            # Raise HTTPException with status 404 for API router
            # Moved import to top: from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
        return instance

    def mock_get_agent_cli(agent_id: str):
        instance = test_state["agent_instances"].get(agent_id)
        if not instance:
            # Use KeyError for CLI compatibility
            raise KeyError(f"Agent '{agent_id}' not found")
        return instance

    monkeypatch.setattr(
        "core.initialization.get_agent", mock_get_agent_api
    )  # Patch canonical source
    monkeypatch.setattr(
        "api.routers.agents.get_agent", mock_get_agent_api
    )  # Patch API usage
    monkeypatch.setattr(
        "cli.main.get_agent", mock_get_agent_cli
    )  # Patch CLI usage with CLI-specific mock

    # Patch get_all_agents to return values from the dict
    monkeypatch.setattr(
        "api.routers.agents.get_all_agents",
        lambda: test_state["agent_instances"],  # Return the dictionary, not just values
    )
    monkeypatch.setattr(
        "cli.main.get_all_agents", lambda: test_state["agent_instances"]
    )

    return test_state  # Return the state dict


# --- Agent Override Fixtures ---


@pytest.fixture
def overridden_security_manager(mock_system_state):
    """Provides the security_manager agent instance with TestModel override."""
    agent = mock_system_state["agent_instances"]["security_manager"]

    # Mock return values for both run and run_async methods
    mock_output = SecurityManagerOutput(
        summary="Test summary from mocked security manager",
        delegated_results=[],
        error=None,
        status="success",  # Add status field for test compatibility
    )

    # Patch both run and run_async methods
    with patch.object(agent, "run", return_value=mock_output), patch.object(
        agent, "run_async", return_value=mock_output
    ):
        yield agent


@pytest.fixture
def overridden_domain_whois_agent(mock_system_state):
    """Provides the domain_whois_agent instance with TestModel override."""
    agent = mock_system_state["agent_instances"]["domain_whois_agent"]

    # Get the mock tool output schema from registry
    SCHEMA_REGISTRY.get("WhoisLookupOutput", dict)  # Default to dict if not found

    # Create expected output for mocking
    expected_output = DomainWhoisOutput(
        domain_name="mocked.com",
        registrar="Test Registrar",
        creation_date="2022-01-01",
        expiration_date="2023-01-01",
        name_servers=["ns1.mock.com", "ns2.mock.com"],
    )

    # Patch the run method instead of using override
    with patch.object(agent, "run", return_value=expected_output):
        yield agent


# --- Refactored Test App Fixture ---


# Note: Removed the direct dependency on mock_agent_dependencies.
# Now depends on mock_system_state which sets up the environment.
@pytest.fixture(scope="function")
def test_app_fixture(mock_system_state):
    """Fixture to create a TestClient instance with mocked system state."""
    # mock_system_state fixture runs automatically, setting up the mocks.

    # Patch the security_manager agent's run and run_async methods to return
    # a response that matches our test expectations
    security_manager = mock_system_state["agent_instances"]["security_manager"]

    # Create expected output matching test case assertions
    mock_output = SecurityManagerOutput(
        summary="Test summary from mocked security manager",
        delegated_results=[],
        error=None,
        status="success",  # Required for test_invoke_agent_success assertions
    )

    # Apply patches - use an async function for run_async
    security_manager.run = MagicMock(return_value=mock_output)

    # Create an async mock for run_async
    async def mock_run_async(*args, **kwargs):
        return mock_output

    security_manager.run_async = mock_run_async

    # Import the app *after* mocks are applied by mock_system_state
    from api.main import app

    client = TestClient(app)
    yield client
