"""NetworkSecurityAgent for scanning networks and endpoints for vulnerabilities.

This agent uses tools like Nuclei from ProjectDiscovery to scan networks, endpoints,
and servers for vulnerabilities. It can operate independently or leverage results
from the DomainAnalyzerAgent for additional context.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field
from pydantic_ai import Agent

from tools.network_tools import nuclei_scan_tool, parse_domain_info_tool


class ScanSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityFinding(BaseModel):
    name: str = Field(..., description="Name of the vulnerability")
    severity: ScanSeverity = Field(
        ..., description="Severity level of the vulnerability"
    )
    description: str = Field(..., description="Description of the vulnerability")
    remediation: Optional[str] = Field(
        None, description="Remediation steps if available"
    )
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    cve_ids: List[str] = Field(
        default_factory=list, description="Associated CVE IDs if applicable"
    )


class NetworkScanResult(BaseModel):
    target: str = Field(..., description="Scanned target (domain, IP, or URL)")
    scan_timestamp: datetime = Field(
        default_factory=datetime.now, description="When the scan was performed"
    )
    vulnerabilities: List[VulnerabilityFinding] = Field(
        default_factory=list, description="List of discovered vulnerabilities"
    )
    summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Summary counts by severity (e.g. {critical: 2, high: 5})",
    )
    scan_details: Dict[str, Any] = Field(
        default_factory=dict, description="Additional scan metadata"
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Agent's recommendations based on findings"
    )


class NetworkSecurityAgentDeps(TypedDict):
    """Dependencies for the NetworkSecurityAgent."""

    domain_info: Optional[Dict[str, Any]]


class NetworkSecurityAgent(Agent[NetworkSecurityAgentDeps, NetworkScanResult]):
    """Agent for analyzing network security using Nuclei and other tools."""

    def __init__(self):
        super().__init__(
            model="openai:gpt-4o",
            deps_type=NetworkSecurityAgentDeps,
            output_type=NetworkScanResult,
            tools=[nuclei_scan_tool, parse_domain_info_tool],
        )

    @Agent.instructions
    def instruction(self) -> str:
        """Provide instructions to the agent on how to perform network security analysis."""
        return """
        You are a Network Security Specialist Agent. Your task is to scan networks,
        endpoints, and servers for vulnerabilities using Nuclei and analyze the results.

        Follow these steps:

        1. If domain_info is provided in the dependencies, review it to understand the
           target better. Use the parse_domain_info_tool to extract relevant
           information.

        2. Use the nuclei_scan_tool to scan the provided target for vulnerabilities.
           - Interpret the nuclei scan results carefully
           - Classify findings by severity
           - Understand the nature of each vulnerability

        3. For each finding, document:
           - Name of the vulnerability
           - Severity level
           - Description
           - Remediation steps (if available)
           - References and CVE IDs

        4. Create a summary of findings grouped by severity

        5. Provide actionable recommendations based on the findings:
           - Prioritize critical and high severity issues
           - Suggest specific remediation steps
           - Recommend additional security measures if appropriate

        6. Return a comprehensive NetworkScanResult containing all findings,
           the summary, and your recommendations.

        Remember that your analysis needs to be accurate, prioritized by risk,
        and actionable for security teams. Focus on providing clear, practical
        recommendations that help improve security posture.
        """

    async def scan_target(
        self,
        target: str,
        domain_info: Optional[Dict[str, Any]] = None,
        severity_filter: Optional[ScanSeverity] = None,
        rate_limit: int = 150,
    ) -> NetworkScanResult:
        """
        Scan a target for security vulnerabilities.

        Args:
            target: The target to scan (domain, IP, or URL)
            domain_info: Optional domain information from DomainAnalyzerAgent
            severity_filter: Optional filter to only include vulnerabilities of
                            specified severity and higher
            rate_limit: Requests per minute limit for the scan

        Returns:
            NetworkScanResult: The results of the security scan with recommendations
        """
        try:
            deps = NetworkSecurityAgentDeps(domain_info=domain_info)
            result = await self.run(
                f"Perform a comprehensive security scan of {target}. "
                + (
                    f"Focus on {severity_filter.value} and higher severity issues."
                    if severity_filter
                    else ""
                ),
                deps=deps,
            )
            return result.output
        except Exception as e:
            # Log the error and return a partial result
            return NetworkScanResult(
                target=target,
                summary={"error": 1},
                scan_details={"error": str(e)},
                recommendations=[
                    "Scan failed. Please try again with different parameters."
                ],
            )


# Create an instance of the agent
network_security_agent = NetworkSecurityAgent()
