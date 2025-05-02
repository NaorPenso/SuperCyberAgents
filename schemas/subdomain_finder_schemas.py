"""Pydantic schemas for the SubdomainFinderTool."""

from typing import List, Optional

from pydantic import BaseModel, Field


class SubdomainFinderInput(BaseModel):
    """Input schema for the SubdomainFinderTool."""

    domain_name: str = Field(..., description="The domain name to find subdomains for.")


class SubdomainFinderOutput(BaseModel):
    """Output schema for the SubdomainFinderTool."""

    domain_name: str = Field(
        ..., description="The domain for which subdomains were searched."
    )
    subdomains: List[str] = Field(
        default_factory=list, description="List of subdomains found."
    )
    error: Optional[str] = Field(
        None, description="Error message if the subdomain finding process failed."
    )
