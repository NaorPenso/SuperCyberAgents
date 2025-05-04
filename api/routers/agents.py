"""API Routers for Pydantic-AI agent interactions.

Placeholder - endpoints will be added as agents are implemented.
"""

import logging
from datetime import datetime
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from agents.domain_analyzer_agent import DomainAnalysisResult, run_domain_analysis
from agents.network_security_agent import NetworkScanResult, ScanSeverity, scan_target
from core.utils import extract_domain

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["Agents"])

# TODO: Add endpoints for Pydantic-AI agents as they are created.

# Placeholder for potential future initialization if needed
# def initialize_system():
#     pass


class DomainAnalysisRequest(BaseModel):
    """Request model for domain analysis."""

    domain: str = Field(..., description="Domain to analyze")
    include_subdomains: bool = Field(False, description="Include subdomain analysis")
    include_whois: bool = Field(False, description="Include WHOIS information")
    include_dns: bool = Field(False, description="Include DNS records")


class DomainAnalysisResponse(BaseModel):
    """Response model for domain analysis."""

    domain: str = Field(..., description="Analyzed domain")
    analysis_id: str = Field(..., description="Unique ID for this analysis")
    timestamp: datetime = Field(..., description="When the analysis was performed")
    results: Dict = Field(..., description="Analysis results")


@router.post("/analyze-domain", response_model=DomainAnalysisResult)
async def analyze_domain_endpoint(
    request: Annotated[DomainAnalysisRequest, Body()],
) -> DomainAnalysisResult:
    """Analyze a domain using the Domain Analyzer Agent."""
    try:
        logger.info(
            f"Received request to analyze domain: {request.domain} "
            f"with options: subdomains={request.include_subdomains}, "
            f"whois={request.include_whois}, dns={request.include_dns}"
        )
        # Call the standalone wrapper function
        analysis_result = await run_domain_analysis(
            domain_to_analyze=request.domain
            # TODO: Consider how to pass include_* flags if needed by the agent logic
            # Currently run_domain_analysis only takes the domain.
            # If the agent prompt/tools need these, run_domain_analysis needs update.
        )
        if analysis_result:
            logger.info(f"Successfully analyzed domain: {request.domain}")
            return analysis_result
        else:
            logger.error(f"Domain analysis failed for {request.domain}")
            raise HTTPException(
                status_code=500,
                detail="Domain analysis failed or returned no result.",
            )
    except Exception as e:
        logger.exception(f"Error during domain analysis for {request.domain}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Error analyzing domain: {e!s}"
        ) from e


# Define the request model locally for the endpoint
class ScanRequest(BaseModel):
    target: str
    use_domain_info: bool = False
    severity_filter: Optional[str] = None  # Keep as string for input flexibility
    rate_limit: int = 150
    # Add other fields corresponding to scan_target parameters if needed


# Use NetworkScanResult as the response model
@router.post("/scan-target", response_model=NetworkScanResult)
async def scan_target_endpoint(
    request: Annotated[ScanRequest, Body()],
) -> NetworkScanResult:
    """Scan a target using the Network Security Agent."""
    try:
        logger.info(f"Received request to scan target: {request.target}")
        domain_analysis_results = None

        if request.use_domain_info:
            domain = extract_domain(request.target)
            if domain:
                logger.info(
                    f"Domain info requested for target {request.target}, "
                    f"extracted domain: {domain}. Fetching info..."
                )
                try:
                    # Call the domain analysis function directly
                    domain_analysis_results = await run_domain_analysis(domain)
                    if domain_analysis_results:
                        logger.info(f"Successfully fetched domain info for {domain}")
                    else:
                        logger.warning(
                            f"Domain analysis for {domain} returned no results."
                        )
                except Exception as domain_e:
                    # Log the error but continue the scan without domain info
                    logger.warning(
                        f"Could not fetch domain info for {domain} "
                        f"due to error: {domain_e}. Proceeding scan without it."
                    )
                    domain_analysis_results = None
            else:
                logger.warning(
                    f"Could not extract domain from target {request.target} "
                    "to fetch domain info."
                )

        # Convert severity string to enum if provided
        severity_enum: Optional[ScanSeverity] = None
        if request.severity_filter:
            try:
                severity_enum = ScanSeverity(request.severity_filter.lower())
            except ValueError as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid severity filter value: {request.severity_filter}. "
                    f"Valid values are: {', '.join([s.value for s in ScanSeverity])}",
                ) from e

        # Call the standalone scan_target function
        scan_result = await scan_target(
            target=request.target,
            domain_info=(
                domain_analysis_results.model_dump()
                if domain_analysis_results
                else None
            ),  # Pass as dict
            severity_filter=severity_enum,
            rate_limit=request.rate_limit,
            # Pass other relevant params from ScanRequest
            # if scan_target accepts them
        )

        if scan_result:
            logger.info(f"Successfully scanned target: {request.target}")
            # Return the NetworkScanResult directly
            return scan_result
        else:
            logger.error(f"Network scan failed for target {request.target}")
            raise HTTPException(
                status_code=500, detail="Network scan failed or returned no result."
            )

    except HTTPException as http_exc:
        # Re-raise HTTPExceptions to preserve status code and details
        raise http_exc
    except Exception as e:
        logger.exception(f"Error during network scan for {request.target}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Error scanning target: {e!s}"
        ) from e


@router.get("/")
async def get_agents_root() -> Dict[str, List[str] | str]:
    """Get the root of the agents router."""
    return {
        "message": "Agent router is active",
        "available_agents": ["domain_analyzer_agent", "network_security_agent"],
    }
