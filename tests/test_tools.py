"""Unit tests for Tools."""

import pytest
from pydantic import ValidationError

from agents.base import ToolConfig  # Import ToolConfig from where it's defined


def test_tool_config_validation():
    """Test ToolConfig validation."""
    valid_data = {
        "name": "valid_tool",
        "description": "Desc",
        "input_schema": "In",
        "output_schema": "Out",
    }
    cfg = ToolConfig(**valid_data)
    assert cfg.name == "valid_tool"

    invalid_data = {"name": "invalid"}  # Missing required fields
    with pytest.raises(ValidationError):
        ToolConfig(**invalid_data)

    invalid_name = valid_data.copy()
    invalid_name["name"] = "Invalid Name"
    with pytest.raises(ValidationError):  # Name must match pattern
        ToolConfig(**invalid_name)
