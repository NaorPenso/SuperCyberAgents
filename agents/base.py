"""Base Pydantic models for agent and tool configurations."""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, Literal, Optional, Type, TypeVar

from pydantic import BaseModel, Field, field_validator

from core.llm_clients import LLMProvider, get_llm_client
from tools.base import BaseTool

# from pydantic_ai.models.instrumented import (
#     InstrumentationSettings,  # Removed
#     InstrumentedModel,
# ) # Removed


# Set up logger for this module
logger = logging.getLogger(__name__)

# Define allowed LLM providers
AllowedProviders = Literal["openai", "azure_openai", "aws_bedrock", "cerebras"]


class ToolRef(BaseModel):
    """Reference to a tool used by an agent."""

    name: str = Field(..., description="Name of the tool (matches ToolConfig.name)")
    alias: str = Field(..., description="Alias used by the agent to refer to the tool")


class AgentConfig(BaseModel):
    """Base configuration model for an agent."""

    id: str = Field(..., description="Unique identifier for the agent")
    description: str = Field(..., description="Description of the agent's purpose")
    enabled: bool = Field(True, description="Whether the agent is enabled")
    llm_provider: Optional[AllowedProviders] = Field(
        None,
        description="LLM provider key. Defaults to DEFAULT_LLM_PROVIDER env var.",
    )
    model: Optional[str] = Field(
        None,
        description="Specific model name for the LLM provider. Defaults to DEFAULT_LLM_MODEL env var.",
    )
    tools: List[ToolRef] = Field(
        default_factory=list, description="List of tools used by the agent"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="LLM parameters (e.g., max_tokens, temperature)",
    )
    input_schema: str = Field(
        ..., description="Name of the Pydantic model for agent input"
    )
    output_schema: str = Field(
        ..., description="Name of the Pydantic model for agent output"
    )

    @field_validator("parameters")
    @classmethod
    def check_params(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate common LLM parameters."""
        if "max_tokens" in params and (
            not isinstance(params["max_tokens"], int) or params["max_tokens"] <= 0
        ):
            raise ValueError("max_tokens must be a positive integer")
        if "temperature" in params:
            temp = params["temperature"]
            if not isinstance(temp, (float, int)) or not (0.0 <= temp <= 2.0):
                raise ValueError("temperature must be a number between 0.0 and 2.0")
        return params


class ToolConfig(BaseModel):
    """Base configuration model for a tool."""

    name: str = Field(
        ...,
        description="Unique identifier for the tool (used in agent config)",
        pattern="^[a-z0-9_]+$",
    )
    description: str = Field(..., description="Description of the tool's function")
    # Example fields from prompt, add more as needed
    endpoint: str | None = Field(None, description="API endpoint if the tool calls one")
    auth_required: bool | None = Field(
        None, description="Whether external auth is needed"
    )
    timeout_sec: int | None = Field(
        None, gt=0, description="API call timeout in seconds"
    )
    input_schema: str = Field(
        ..., description="Name of the Pydantic model for tool input"
    )
    output_schema: str = Field(
        ..., description="Name of the Pydantic model for tool output"
    )


# --- Base Agent Class --- #
InputType = TypeVar("InputType", bound=BaseModel)
OutputType = TypeVar("OutputType", bound=BaseModel)


class BaseAgent(ABC, Generic[InputType, OutputType]):
    """Abstract base class for all agents."""

    config: AgentConfig  # Pydantic config for this agent
    tools: Dict[str, Any]  # Changed to Dict for alias lookup
    # Class attributes for schema definition (used by subclasses)
    input_schema: Type[InputType]
    output_schema: Type[OutputType]
    # Instance attributes holding the resolved schema classes (set during init)
    input_schema_class: Type[InputType]
    output_schema_class: Type[OutputType]

    llm_client: Any  # Placeholder for the LLM client instance
    model_name: str  # Store the specific model name for this agent

    def __init__(
        self, config: AgentConfig, tools: List[BaseTool], instrument: bool = True
    ):
        """Initialize the agent with config and a list of tool instances."""
        self.config = config
        self.id = config.id
        self.tools: Dict[str, BaseTool] = {}
        self.model_name = config.model or os.getenv(
            f"{config.llm_provider.upper()}_MODEL_NAME"
        )
        self.llm_client: LLMProvider  # Simplified type hint
        self._available_agents_info: str = ""  # Cache for planning prompt

        # --- Map Tool Instances using Config Aliases --- #
        # Create a temporary map of tool names to their instances
        tool_instance_map = {tool.name: tool for tool in tools}

        # Build the self.tools dictionary using the alias from config
        # and mapping to the correct instance via the tool name.
        for tool_ref in config.tools:
            instance = tool_instance_map.get(tool_ref.name)
            if instance:
                self.tools[tool_ref.alias] = instance
            else:
                # This should ideally not happen if initialization logic is correct
                error_msg = f"Agent '{self.id}': Tool '{tool_ref.name}' referenced in config not found in provided instances."
                logger.error(error_msg)
                raise ValueError(error_msg)
        # --- End Tool Mapping --- #

        # Retrieve and store the LLM client
        try:
            self.llm_client = get_llm_client(config.llm_provider)

            logger.info(
                f"Agent '{self.id}': Successfully initialized LLM client for provider '{config.llm_provider}'"
            )
        except ValueError as e:
            logger.error(f"Agent '{self.id}': Failed to initialize LLM client: {e}")
            raise  # Re-raise to prevent agent loading without a client

    @abstractmethod
    def run(self, input_data: InputType) -> OutputType:
        """Execute the agent's logic and return the output."""
        raise NotImplementedError(
            f"Agent {self.__class__.__name__} must implement the run method."
        )

    async def run_async(self, input_data: InputType) -> OutputType:
        """Async wrapper around the synchronous run method for API compatibility.

        In the future, this could be implemented with true async/await patterns.
        """
        return self.run(input_data)
