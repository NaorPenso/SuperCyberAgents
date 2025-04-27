"""Tool for delegating tasks to other agents."""

import importlib
import logging
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agents.base import ToolConfig  # Correct import path
from core.initialization import get_agent  # To find the agent instance
from schemas.delegate_task_schemas import DelegateTaskInput, DelegateTaskOutput
from schemas.registry import SCHEMA_REGISTRY  # Import the registry
from tools import register_tool
from tools.base import BaseTool

# We need a way to find schema classes, similar to API/CLI
# Ideally, centralize this helper in core.schemas or core.utils

logger = logging.getLogger(__name__)

# --- Helper to dynamically load schemas (copied from cli/main.py - needs centralization) --- #
schema_modules = []
project_root = Path(__file__).parent.parent.parent
schemas_dir = project_root / "schemas"
try:
    if (schemas_dir / "__init__.py").exists():

        # Import known base schema modules first if they exist
        try:
            agent_schemas = importlib.import_module("schemas.agent_schemas")
            schema_modules.append(agent_schemas)
        except ImportError:
            pass
        try:
            tool_schemas = importlib.import_module("schemas.tool_schemas")
            schema_modules.append(tool_schemas)
        except ImportError:
            pass

        # Import other schema files dynamically
        for f in schemas_dir.glob("*_schemas.py"):
            if f.name not in ["agent_schemas.py", "tool_schemas.py", "__init__.py"]:
                module_name = f"schemas.{f.stem}"
                try:
                    module = importlib.import_module(module_name)
                    schema_modules.append(module)
                    logging.debug(
                        f"Dynamically loaded schema module for DelegateTool: {module_name}"
                    )
                except ImportError as ie:
                    logging.warning(
                        f"DelegateTool could not import schema module {module_name}: {ie}"
                    )
    else:
        logging.error(f"Schemas directory or __init__.py not found at {schemas_dir}")

except Exception as e:
    logging.error(f"Error loading schema modules for DelegateTool: {e}")


def _get_schema_class(schema_name: str) -> type[BaseModel] | None:
    """Find a Pydantic schema class by its name using the registry."""
    return SCHEMA_REGISTRY.get(schema_name)


# --- End Helper --- #


@register_tool(name="delegate_task_tool")
class DelegateTaskTool(BaseTool[DelegateTaskInput, DelegateTaskOutput]):
    """Delegates a task to another specified agent."""

    input_schema = DelegateTaskInput
    output_schema = DelegateTaskOutput

    def __init__(self, config: ToolConfig):
        super().__init__(config)

    def execute(self, input_data: DelegateTaskInput) -> DelegateTaskOutput:
        """Execute the delegation.

        Note: This implementation does not currently handle passing RunContext
              for aggregated usage tracking due to framework limitations.
        """
        target_agent_id = input_data.agent_id
        target_agent_input_dict = input_data.agent_input
        logger.info(f"Attempting to delegate task to agent: {target_agent_id}")

        # 1. Find the target agent instance
        target_agent = get_agent(target_agent_id)
        if not target_agent:
            err_msg = f"Delegate target agent '{target_agent_id}' not found."
            logger.error(err_msg)
            return DelegateTaskOutput(
                agent_id=target_agent_id, status="error", error_message=err_msg
            )

        # 2. Find and validate the input schema for the target agent
        input_schema_name = target_agent.config.input_schema
        input_schema_class = _get_schema_class(input_schema_name)
        if not input_schema_class:
            err_msg = f"Input schema '{input_schema_name}' for target agent '{target_agent_id}' could not be found."
            logger.error(err_msg)
            return DelegateTaskOutput(
                agent_id=target_agent_id, status="error", error_message=err_msg
            )

        # 3. Validate the provided input against the target agent's schema
        try:
            validated_input = input_schema_class(**target_agent_input_dict)
            logger.debug(f"Validated input for {target_agent_id} successfully.")
        except ValidationError as e:
            err_msg = f"Input validation failed for agent '{target_agent_id}': {e}"
            logger.warning(err_msg)
            # Return validation error details if helpful
            return DelegateTaskOutput(
                agent_id=target_agent_id, status="error", error_message=err_msg
            )
        except Exception as e:
            err_msg = f"Unexpected error during input validation for agent '{target_agent_id}': {e}"
            logger.exception(err_msg)
            return DelegateTaskOutput(
                agent_id=target_agent_id, status="error", error_message=err_msg
            )

        # 4. Execute the target agent
        try:
            logger.info(f"Running target agent: {target_agent_id}")
            # TODO: Explore passing RunContext/usage if framework allows future enhancements
            agent_output = target_agent.run(validated_input)
            logger.info(f"Target agent '{target_agent_id}' finished successfully.")

            # Ensure output is a Pydantic model before dumping
            if not isinstance(agent_output, BaseModel):
                err_msg = (
                    f"Target agent '{target_agent_id}' did not return a Pydantic model."
                )
                logger.error(err_msg)
                return DelegateTaskOutput(
                    agent_id=target_agent_id, status="error", error_message=err_msg
                )

            return DelegateTaskOutput(
                agent_id=target_agent_id,
                status="success",
                result=agent_output.model_dump(),  # Return result as dict
            )

        except Exception as e:
            err_msg = f"Execution failed for target agent '{target_agent_id}': {e}"
            logger.exception(err_msg)
            return DelegateTaskOutput(
                agent_id=target_agent_id, status="error", error_message=err_msg
            )
