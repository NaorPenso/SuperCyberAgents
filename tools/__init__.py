"""Tools package initialization and registry."""

from typing import Dict, Type

from tools.base import BaseTool

TOOL_REGISTRY: Dict[str, Type[BaseTool]] = {}


# type: ignore[misc] # Decorator return type issue with Type[BaseTool]
def register_tool(name: str | None = None):
    """Class decorator factory to register tool classes.

    Args:
        name: The name to register the tool under. If None, uses the class name.
              This name should ideally match the 'name' in the tool's YAML config.

    Returns:
        A decorator function.
    """

    def decorator(cls: Type[BaseTool]) -> Type[BaseTool]:
        key = name or cls.__name__
        if key in TOOL_REGISTRY:
            raise ValueError(f"Tool with name '{key}' already registered.")
        TOOL_REGISTRY[key] = cls
        return cls

    return decorator
