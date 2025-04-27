"""API Routers for agent interactions."""

# import importlib # Removed
import logging
# from pathlib import Path # Removed
from typing import Any, Dict

import pydantic
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.initialization import get_agent, get_all_agents
from schemas.registry import SCHEMA_REGISTRY # Import the registry

# Remove direct schema imports, load dynamically instead
# from schemas import agent_schemas, tool_schemas # Needed to resolve schema names

logger = logging.getLogger(__name__)

router = APIRouter()

# Remove Dynamic Schema Loading
# schema_modules = []
# # Determine project root relative to this file
# project_root = Path(__file__).parent.parent.parent
# schemas_dir = project_root / "schemas"
# try:
#     # Import base schema modules first if they exist
#     if (schemas_dir / "agent_schemas.py").exists():
#         import schemas.agent_schemas
#
#         schema_modules.append(schemas.agent_schemas)
#     if (schemas_dir / "tool_schemas.py").exists():
#         import schemas.tool_schemas
#
#         schema_modules.append(schemas.tool_schemas)
#
#     # Import other schema files dynamically
#     for f in schemas_dir.glob("*_schemas.py"):
#         if f.name not in ["agent_schemas.py", "tool_schemas.py", "__init__.py"]:
#             module_name = f"schemas.{f.stem}"
#             try:
#                 module = importlib.import_module(module_name)
#                 schema_modules.append(module)
#                 logging.debug(f"Dynamically loaded schema module: {module_name}")
#             except ImportError as ie:
#                 logging.warning(f"Could not import schema module {module_name}: {ie}")
# except Exception as e:
#     logging.error(f"Error loading schema modules for API: {e}")


# --- Helper to get schema class by name ---
def _get_schema_class(schema_name: str) -> type[BaseModel] | None:
    """Find a Pydantic schema class by its name using the registry."""
    # for module in schema_modules: # Removed loop
    #     if hasattr(module, schema_name):
    #         cls = getattr(module, schema_name)
    #         if isinstance(cls, type) and issubclass(cls, BaseModel):
    #             return cls
    # return None
    return SCHEMA_REGISTRY.get(schema_name)


# --- API Models ---
class InvokeRequest(BaseModel):
    """Request model for invoking an agent."""

    input: Dict[str, Any] = pydantic.Field(
        ..., description="Input data for the agent, must match agent's input schema."
    )


class InvokeResponse(BaseModel):
    """Response model for agent invocation."""

    agent_id: str = pydantic.Field(..., description="The ID of the invoked agent.")
    output: Dict[str, Any] = pydantic.Field(
        ..., description="Output data from the agent, matches agent's output schema."
    )


class AgentInfo(BaseModel):
    """Information about a loaded agent."""

    id: str
    description: str
    llm_provider: str
    model: str
    input_schema_name: str
    output_schema_name: str
    tools: list[str]  # List of tool aliases used


# --- API Endpoints ---
@router.get("/")
async def list_available_agents() -> list[AgentInfo]:
    """List all currently loaded and enabled agents."""
    agents_map = get_all_agents()
    agent_list = []
    for _agent_id, agent_instance in agents_map.items():
        agent_list.append(
            AgentInfo(
                id=agent_instance.config.id,
                description=agent_instance.config.description,
                llm_provider=agent_instance.config.llm_provider,
                model=agent_instance.config.model,
                input_schema_name=agent_instance.config.input_schema,
                output_schema_name=agent_instance.config.output_schema,
                tools=[tool_ref.alias for tool_ref in agent_instance.config.tools],
            )
        )
    return agent_list


@router.post("/{agent_id}/invoke", response_model=InvokeResponse)
async def invoke_agent(agent_id: str, request: InvokeRequest):
    """Invoke a specific agent with the provided input."""
    logger.info(f"Received request to invoke agent: {agent_id}")
    agent = get_agent(agent_id)

    if not agent:
        logger.warning(f"Agent '{agent_id}' not found or not loaded.")
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Dynamically get the expected input schema class
    input_schema_class = _get_schema_class(agent.config.input_schema)
    if not input_schema_class:
        logger.error(
            f"Input schema '{agent.config.input_schema}' for agent '{agent_id}' not found."
        )
        raise HTTPException(
            status_code=500, detail="Agent input schema configuration error."
        )

    # Validate the input data against the agent's specific input schema
    try:
        input_obj = input_schema_class(**request.input)
        logger.debug(f"Validated input for agent '{agent_id}'.")
    except pydantic.ValidationError as e:
        logger.warning(f"Invalid input for agent '{agent_id}': {e}")
        raise HTTPException(status_code=400, detail=f"Invalid input data: {e}") from e

    # Run the agent
    logger.info(f"Executing agent '{agent_id}' with validated input...")
    try:
        # TODO: Consider adding usage limits from config or request
        # usage_limits = UsageLimits(...)
        # result = await agent.run(validated_input, usage_limits=usage_limits)
        agent_output = await agent.run(input_obj)
        logger.info(f"Agent '{agent_id}' execution successful.")

        # Convert Pydantic model output to dict for API response
        if isinstance(agent_output, BaseModel):
            output_data = agent_output.model_dump(mode="json")
        else:
            output_data = agent_output  # Assume already JSON-serializable

        return output_data

    except Exception as e:
        logger.exception(f"Error during agent '{agent_id}' execution: {e}")
        # Potentially map specific agent errors to HTTP status codes
        raise HTTPException(
            status_code=500, detail=f"Agent execution failed: {e}"
        ) from e
