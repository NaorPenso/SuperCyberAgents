"""Pydantic schemas for the Domain WHOIS Agent and Tool."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from schemas import register_schema # Import the decorator


@register_schema("DomainWhoisInput") # Register with class name
class DomainWhoisInput(BaseModel):
    """Input schema for the Domain WHOIS Agent."""

    domain: str = Field(..., description="The domain name to perform WHOIS lookup on.")


@register_schema("DomainWhoisOutput") # Register with class name
class DomainWhoisOutput(BaseModel):
    """Output schema for the DomainWhoisAgent.

    Contains structured WHOIS information or an error message.
    """

    domain_name: str = Field(..., description="The domain name queried.")
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
    emails: List[str] = Field(
        default_factory=list, description="Contact emails found in the record."
    )
    dnssec: Optional[str] = Field(None, description="DNSSEC status (e.g., 'unsigned').")
    updated_date: Optional[datetime] = Field(
        None, description="Last updated timestamp."
    )
    raw_data: Optional[str] = Field(
        None, description="Raw WHOIS response text, if available."
    )
    error: Optional[str] = Field(
        None, description="Error message if the lookup or processing failed."
    )
