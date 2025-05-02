"""API Routers for Pydantic-AI agent interactions.

Placeholder - endpoints will be added as agents are implemented.
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agents.domain_analyzer_agent import domain_analyzer_agent
from agents.network_security_agent import (
    NetworkScanResult,
    ScanSeverity,
    network_security_agent,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# TODO: Add endpoints for Pydantic-AI agents as they are created.

# Placeholder for potential future initialization if needed
# def initialize_system():
#     pass


class DomainAnalysisRequest(BaseModel):
    """Request model for domain analysis."""

    domain: str = Field(..., description="Domain to analyze")
    include_subdomains: bool = Field(False, description="Include subdomain analysis")
    include_whois: bool = Field(True, description="Include WHOIS information")
    include_dns: bool = Field(True, description="Include DNS records")


class DomainAnalysisResponse(BaseModel):
    """Response model for domain analysis."""

    domain: str = Field(..., description="Analyzed domain")
    analysis_id: str = Field(..., description="Unique ID for this analysis")
    timestamp: datetime = Field(..., description="When the analysis was performed")
    results: Dict = Field(..., description="Analysis results")


@router.post(
    "/analyze-domain",
    response_model=DomainAnalysisResponse,
    description="Analyze a domain for cybersecurity insights",
)
async def analyze_domain(request: DomainAnalysisRequest):
    """Analyze a domain using the DomainAnalyzerAgent."""
    try:
        result = await domain_analyzer_agent.analyze_domain(
            request.domain,
            include_subdomains=request.include_subdomains,
            include_whois=request.include_whois,
            include_dns=request.include_dns,
        )

        return DomainAnalysisResponse(
            domain=request.domain,
            analysis_id=result.analysis_id,
            timestamp=result.timestamp,
            results=result.model_dump(exclude={"analysis_id", "timestamp"}),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing domain: {e!s}")


class NetworkScanRequest(BaseModel):
    """Request model for network security scanning."""

    target: str = Field(..., description="Target URL, domain, or IP to scan")
    severity_filter: Optional[ScanSeverity] = Field(
        None, description="Only include vulnerabilities of this severity and higher"
    )
    rate_limit: int = Field(
        150, description="Maximum requests per minute", ge=10, le=1000
    )
    use_domain_info: bool = Field(
        False, description="Use results from domain analysis if available"
    )


@router.post(
    "/scan-target",
    response_model=NetworkScanResult,
    description="Scan a target for security vulnerabilities using Nuclei",
)
async def scan_target(request: NetworkScanRequest):
    """Scan a target for security vulnerabilities using the NetworkSecurityAgent."""
    try:
        # If domain info is requested, try to get it first
        domain_info = None
        if request.use_domain_info and request.target:
            try:
                # Extract the domain from the target
                from urllib.parse import urlparse

                parsed = urlparse(
                    request.target
                    if "//" in request.target
                    else f"http://{request.target}"
                )
                domain = parsed.netloc or parsed.path
                domain = domain.split(":")[0]  # Remove port if present

                # Get domain info if it's a valid domain
                if "." in domain:
                    domain_result = await domain_analyzer_agent.analyze_domain(
                        domain,
                        include_subdomains=True,
                        include_whois=True,
                        include_dns=True,
                    )
                    domain_info = domain_result.model_dump(
                        exclude={"analysis_id", "timestamp"}
                    )
            except Exception:
                # Log the error but continue without domain info
                pass

        # Run the security scan
        result = await network_security_agent.scan_target(
            target=request.target,
            domain_info=domain_info,
            severity_filter=request.severity_filter,
            rate_limit=request.rate_limit,
        )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning target: {e!s}")


@router.get("/")
async def get_agents_root():
    """Root endpoint for the agents router."""
    return {
        "message": "Agent router is active",
        "available_agents": ["domain_analyzer_agent", "network_security_agent"],
    }
