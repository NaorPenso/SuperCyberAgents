"""Agents package initialization and registry."""

from typing import Dict, Type

from agents.base import BaseAgent

AGENT_REGISTRY: Dict[str, Type[BaseAgent]] = {}


# type: ignore[misc] # Decorator return type issue with Type[BaseAgent]
def register_agent(name: str | None = None):
    """Class decorator factory to register agent classes.

    Args:
        name: The name to register the agent under. If None, uses the class name.
              This name should ideally match the 'id' in the agent's YAML config.

    Returns:
        A decorator function.
    """

    def decorator(cls: Type[BaseAgent]) -> Type[BaseAgent]:
        key = name or cls.__name__
        if key in AGENT_REGISTRY:
            raise ValueError(f"Agent with name '{key}' already registered.")
        AGENT_REGISTRY[key] = cls
        return cls

    return decorator
