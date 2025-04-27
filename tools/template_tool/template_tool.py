"""Placeholder for a template tool implementation."""

import logging

from agents.base import ToolConfig
from schemas.template_tool_schemas import TemplateToolInput, TemplateToolOutput
from tools import register_tool
from tools.base import BaseTool

logger = logging.getLogger(__name__)

# Example Input/Output Schemas (defined in schemas/template_tool_schemas.py)
# class TemplateToolInput(BaseModel):
#     parameter: str
#
# class TemplateToolOutput(BaseModel):
#     result: str


@register_tool(name="template_tool")
class TemplateTool(BaseTool[TemplateToolInput, TemplateToolOutput]):
    """A template tool that performs a simple operation."""

    input_schema = TemplateToolInput
    output_schema = TemplateToolOutput

    def __init__(self, config: ToolConfig):
        super().__init__(config)
        # Add any initialization specific to this tool

    def execute(self, input_data: TemplateToolInput) -> TemplateToolOutput:
        """Execute the template tool's logic."""
        logger.info(f"Executing TemplateTool with input: {input_data.parameter}")

        # --- Tool Logic Start --- #
        processed_result = f"Processed: {input_data.parameter.upper()}"
        # --- Tool Logic End --- #

        logger.info(f"TemplateTool finished. Result: {processed_result}")
        return TemplateToolOutput(result=processed_result)
