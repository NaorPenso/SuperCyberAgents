"""Shared fixtures for tests."""

import os
import sys

import pydantic_ai.models  # Import the module directly
import pytest
from _pytest.monkeypatch import MonkeyPatch

# Add the project root to the Python path - might be needed for discovery
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Disable actual LLM API calls during tests
# Set flag directly without using the non-existent function
pydantic_ai.models.ALLOW_MODEL_REQUESTS = False


# --- Session-scoped monkeypatch fixture ---
@pytest.fixture(scope="session")
def monkeysession():
    """Create a session-scoped monkeypatch fixture."""
    mpatch = MonkeyPatch()
    yield mpatch # pragma: no cover
    mpatch.undo() # pragma: no cover


# --- Removed Old Framework Fixtures --- #
# Fixtures like mock_system_state, register_mock_schemas, agent overrides,
# test_app_fixture etc. related to the old framework have been removed.
# New fixtures will be added as needed for Pydantic-AI testing.
