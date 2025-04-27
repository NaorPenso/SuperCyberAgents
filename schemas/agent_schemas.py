"""Pydantic schemas for agent inputs and outputs."""

import datetime

from pydantic import BaseModel, Field


class ExampleAgentInput(BaseModel):
    """Input schema for the ExampleAgent."""

    log_entry: str = Field(..., description="A single log entry to analyze")
    target_ip: str | None = Field(None, description="Optional target IP from the log")


class ExampleAgentOutput(BaseModel):
    """Output schema for the ExampleAgent."""

    analysis_summary: str = Field(..., description="Summary from LLM analysis")
    ip_reputation: str | None = Field(
        None, description="Reputation result if IP lookup tool was used"
    )
    is_suspicious: bool = Field(
        False, description="Whether the agent deemed the entry suspicious"
    )
    processed_at: datetime.datetime = Field(
        default_factory=datetime.datetime.utcnow,
        description="Timestamp of processing",
    )


# Add other agent-specific schemas below
# class LogMonitorInput(BaseModel):
#     log_file_path: str
#     severity_filter: str

# class LogMonitorOutput(BaseModel):
#     alerts: List[str]
#     summary: str
