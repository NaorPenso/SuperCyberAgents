"""Pydantic schemas for the SecurityManagerAgent."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas import register_schema


@register_schema("SecurityManagerInput")
class SecurityManagerInput(BaseModel):
    """Input schema for the SecurityManagerAgent."""

    task_description: str = Field(
        ..., description="The overall security task or analysis goal to be managed."
    )
    # Optional: Add fields for specific context if needed, e.g., target_asset: str
    error_message: Optional[str] = Field(None, description="Error message if delegation failed")


class DelegatedTaskResult(BaseModel):
    """Represents the result from a single delegated task."""

    agent_id: str = Field(
        ..., description="The ID of the agent that executed the task."
    )
    status: str = Field(
        ..., description="Status of the delegation ('success' or 'error')."
    )
    result: Optional[Dict[str, Any]] = Field(
        None,
        description="The structured output from the delegate agent, if successful.",
    )
    error_message: Optional[str] = Field(
        None, description="Error message if delegation or agent execution failed."
    )


@register_schema("SecurityManagerOutput")
class SecurityManagerOutput(BaseModel):
    """Output schema for the SecurityManagerAgent."""

    summary: str = Field(
        ..., description="A summary of the findings from delegated tasks."
    )
    delegated_results: List[DelegatedTaskResult] = Field(
        default_factory=list,
        description="List of results from each delegated agent task.",
    )
    error: Optional[str] = Field(
        None, description="Error message if the overall management process failed."
    )
