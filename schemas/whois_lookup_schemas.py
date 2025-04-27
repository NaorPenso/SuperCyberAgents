"""Pydantic schemas for the WhoisLookupTool."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from schemas import register_schema


@register_schema("WhoisLookupInput")
class WhoisLookupInput(BaseModel):
    """Input schema for the WhoisLookupTool."""

    domain: str = Field(..., description="The domain name to look up.")


@register_schema("WhoisLookupOutput")
class WhoisLookupOutput(BaseModel):
    """Output schema for the WhoisLookupTool.

    Mirrors the fields needed by DomainWhoisAgentOutput for easy mapping.
    Includes raw data and potential tool-level errors.
    """

    domain_name: Optional[str] = Field(None, description="Queried domain name.")
    registrar: Optional[str] = Field(None, description="Domain registrar name.")
    creation_date: Optional[datetime] = Field(
        None, description="Domain creation timestamp."
    )
    expiration_date: Optional[datetime] = Field(
        None, description="Domain expiration timestamp."
    )
    name_servers: List[str] = Field(
        default_factory=list, description="List of name servers."
    )
    status: List[str] = Field(
        default_factory=list, description="List of domain statuses."
    )
    emails: List[str] = Field(default_factory=list, description="Contact emails found.")
    dnssec: Optional[str] = Field(None, description="DNSSEC status.")
    updated_date: Optional[datetime] = Field(
        None, description="Last updated timestamp."
    )
    raw_data: Optional[str] = Field(None, description="Raw WHOIS response text.")
    error: Optional[str] = Field(None, description="Error message if lookup failed.")
