"""Pydantic schemas for the VirusTotal Tool."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VirusTotalInput(BaseModel):
    """Input schema for the VirusTotal Tool."""

    resource: str = Field(
        ..., description="The resource to query (domain, IP, URL, or hash)"
    )
    resource_type: str = Field(
        "domain", description="Type of resource ('domain', 'ip', 'url', 'file')"
    )


class VirusTotalOutput(BaseModel):
    """Output schema for the VirusTotal Tool.

    Contains structured analysis data from VirusTotal or an error message.
    """

    resource: str = Field(..., description="The resource that was queried")
    analysis_link: Optional[str] = Field(
        None, description="Link to the full VirusTotal analysis"
    )
    # Common fields across resource types
    last_analysis_stats: Optional[Dict[str, int]] = Field(
        None, description="Detection stats (malicious, suspicious, etc.)"
    )
    last_analysis_date: Optional[str] = Field(
        None, description="Timestamp of the last analysis"
    )
    reputation: Optional[int] = Field(None, description="Overall reputation score")
    # Domain/IP specific
    whois: Optional[str] = Field(None, description="Raw WHOIS data from VT")
    resolutions: Optional[List[Dict]] = Field(
        None, description="IP address resolutions"
    )
    detected_urls: Optional[List[Dict]] = Field(
        None, description="URLs detected on the domain/IP"
    )
    # URL specific
    title: Optional[str] = Field(None, description="Title of the scanned URL")
    # File specific
    names: Optional[List[str]] = Field(None, description="Known names of the file")
    type_description: Optional[str] = Field(
        None, description="Description of file type"
    )
    # Generic raw data
    raw_data: Optional[Dict[str, Any]] = Field(
        None, description="Raw JSON response from VirusTotal API"
    )
    error: Optional[str] = Field(
        None, description="Error message if the VirusTotal lookup failed."
    )
