"""Pydantic schemas for the Shodan Tool."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ShodanInput(BaseModel):
    """Input schema for the Shodan Tool."""

    query: str = Field(
        ..., description="The Shodan search query (e.g., domain, IP, hostname)"
    )
    query_type: str = Field(
        "host",
        description=(
            "Type of query ('host' for IP/hostname, 'search' for general query)"
        ),
    )


class ShodanHostOutput(BaseModel):
    """Schema for a single host result from Shodan."""

    ip_str: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None  # 'tcp' or 'udp'
    hostnames: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    os: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    location: Optional[Dict[str, Any]] = None
    vulns: Optional[List[str]] = Field(default_factory=list)  # List of CVEs
    data: Optional[str] = None  # Banner data
    timestamp: Optional[str] = None


class ShodanOutput(BaseModel):
    """Output schema for the Shodan Tool.

    Contains structured data from Shodan or an error message.
    """

    query: str = Field(..., description="The query that was executed")
    total_results: Optional[int] = Field(
        None, description="Total number of results found for search queries"
    )
    matches: List[ShodanHostOutput] = Field(
        default_factory=list, description="List of matching hosts or search results"
    )
    raw_data: Optional[Any] = Field(
        None, description="Raw JSON response from Shodan API"
    )
    error: Optional[str] = Field(
        None, description="Error message if the Shodan lookup failed."
    )
