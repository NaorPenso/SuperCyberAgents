"""Pydantic schemas for tool inputs and outputs."""

from typing import Dict

from pydantic import BaseModel, Field, IPvAnyAddress


class IPLookupInput(BaseModel):
    """Input schema for the IPLookupTool."""

    ip_address: IPvAnyAddress = Field(..., description="The IP address to look up")


class IPLookupOutput(BaseModel):
    """Output schema for the IPLookupTool."""

    ip_address: str = Field(..., description="The IP address that was looked up")
    reputation: str = Field(
        ..., description="Reputation score or category (e.g., 'benign', 'malicious')"
    )
    details: Dict | None = Field(
        None, description="Additional details from the threat intel source"
    )


# Add other tool-specific schemas below
