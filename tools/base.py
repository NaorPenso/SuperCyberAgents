"""Base classes for tools."""

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, Type, TypeVar

from pydantic import BaseModel

# Avoid circular import
if TYPE_CHECKING:
    from agents.base import ToolConfig


InputType = TypeVar("InputType", bound=BaseModel)
OutputType = TypeVar("OutputType", bound=BaseModel)

logger = logging.getLogger(__name__)


class BaseTool(ABC, Generic[InputType, OutputType]):
    """Abstract base class for all tools."""

    config: "ToolConfig"  # The Pydantic config for this tool
    input_schema: Type[InputType]  # Expected input model type
    output_schema: Type[OutputType]  # Expected output model type

    def __init__(self, config: "ToolConfig"):
        """Initialize the tool with its configuration."""
        self.config = config
        self.name = config.name
        self.description = config.description

    @abstractmethod
    def execute(self, input_data: InputType) -> OutputType:
        """Perform the tool's function and return output."""
        raise NotImplementedError(
            f"Tool {self.__class__.__name__} must implement the execute method."
        )
