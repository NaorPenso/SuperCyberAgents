"""Pydantic schemas for the Security Manager Agent."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Enum for threat levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitorSpec(BaseModel):
    """Specification for what the Security Manager should monitor."""

    monitor_type: str = Field(
        ..., description="Type of monitoring (e.g., 'log', 'network')"
    )
    config: Dict[str, Any] = Field(
        ..., description="Configuration specific to the monitor type"
    )


class AnalysisRequest(BaseModel):
    """Input schema for requesting analysis from the Security Manager."""

    request_id: str = Field(..., description="Unique identifier for this request.")
    spec: MonitorSpec = Field(..., description="The monitoring specification.")
    context_data: Optional[Dict[str, Any]] = Field(
        None, description="Optional additional context for the analysis."
    )


class AnalysisResult(BaseModel):
    """Output schema for the analysis result from the Security Manager."""

    request_id: str = Field(..., description="The ID of the original analysis request.")
    threat_level: ThreatLevel = Field(..., description="Overall assessed threat level.")
    summary: str = Field(..., description="A concise summary of the analysis findings.")
    details: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of detailed findings or evidence."
    )
    recommended_actions: Optional[List[str]] = Field(
        None, description="Optional list of recommended actions."
    )


class SecurityManagerInput(BaseModel):
    """Input schema for the SecurityManagerAgent."""

    task_description: str = Field(
        ..., description="The overall security task or analysis goal to be managed."
    )
    # Optional: Add fields for specific context if needed, e.g., target_asset: str
    error_message: Optional[str] = Field(
        None, description="Error message if delegation failed"
    )


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
    status: str = Field(
        "success", description="Status of the overall execution ('success' or 'error')"
    )
