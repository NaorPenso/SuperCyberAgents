"""Agents package for Pydantic-AI agent implementations."""

# This file is intentionally left sparse after removing the old registry.
# Pydantic-AI agents will be defined in submodules.

from .domain_analyzer_agent import domain_analyzer_agent
from .network_security_agent import network_security_agent

"""Expose agents for easy import."""

__all__ = [
    "domain_analyzer_agent",
    "network_security_agent",
]
