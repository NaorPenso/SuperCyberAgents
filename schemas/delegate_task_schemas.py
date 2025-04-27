"""Pydantic schemas for the Delegate Task Tool."""

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from schemas import register_schema


@register_schema("DelegateTaskInput")
class DelegateTaskInput(BaseModel):
    """Input schema for delegating a task to another agent."""

    agent_id: str = Field(
        ..., description="The unique ID of the agent to delegate the task to."
    )
    agent_input: Dict[str, Any] = Field(
        ...,
        description="The input data (as a dictionary) to be passed to the target agent's run method.",
    )


@register_schema("DelegateTaskOutput")
class DelegateTaskOutput(BaseModel):
    """Output schema for the result of a delegated task."""

    agent_id: str = Field(
        ..., description="The ID of the agent the task was delegated to."
    )
    status: str = Field(
        ..., description="Status of the delegation attempt ('success' or 'error')."
    )
    result: Optional[Dict[str, Any]] = Field(
        None,
        description="The structured output (as a dictionary) from the delegate agent, if successful.",
    )
    error_message: Optional[str] = Field(
        None, description="Error message if delegation or agent execution failed."
    )
