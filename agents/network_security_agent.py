# ruff: noqa: E501
"""NetworkSecurityAgent for scanning networks and endpoints for vulnerabilities.

This agent uses tools like Nuclei from ProjectDiscovery to scan networks, endpoints,
and servers for vulnerabilities. It can operate independently or leverage results
from the DomainAnalyzerAgent for additional context.
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.exceptions import (
    AgentRunError,
    ModelHTTPError,
    UnexpectedModelBehavior,
    UsageLimitExceeded,
)
from pydantic_ai.usage import UsageLimits

from tools.network_tools import (
    nuclei_scan_tool_instance,
    parse_domain_info_tool_instance,
)

# Get logger instance
logger = logging.getLogger(__name__)

# fmt: off
NETWORK_SECURITY_AGENT_PROMPT = """
        You are a Network Security Analyst Agent. Your primary goal is **accurate reporting**
        of security scan results, whether vulnerabilities are found or not. You perform
        comprehensive security scans using the `nuclei_scan_tool` and provide
        actionable recommendations based on the findings.

        Workflow:
        1. Receive the target (domain, IP, or URL) and optional context (e.g.,
           domain information from DomainAnalyzerAgent, severity filter).
           **If `domain_info` is provided but seems incomplete or missing expected fields, proceed with the scan but note this limitation.**

        2. **Determine the appropriate parameters for `nuclei_scan_tool`:**
           - **Targeting:** Always use the primary `target` provided.
           - **Template Selection:**
             - If specific templates or workflows are requested (e.g., "scan for log4j", "run cves workflow", "use template x.yaml"), use the `templates` or `workflows` parameter.
             - If exclusion of specific templates/workflows is needed, use the `exclude_templates` parameter.
             - Consider `automatic_scan: True` for broad web scans if appropriate.
             - Use `new_templates: True` if asked to scan only with the latest templates.
           - **Filtering (Fine-tuning Scan Scope):**
             - Use `severity` (e.g., `["high", "critical"]`) if the user specifies severity levels. Remember it filters for that level AND higher by default.
             - Use `exclude_severity` to explicitly remove lower severities.
             - Use `tags` (e.g., `["wordpress", "cve"]`) or `exclude_tags` based on user requests for specific technologies or vulnerability types.
             - Use `author`, `template_id`, `exclude_id`, `protocol_type` if the user provides very specific filtering criteria.
           - **Rate Limiting & Concurrency:**
             - Default `rate_limit` is 150. Adjust *only* if explicitly requested (e.g., "scan faster", "scan slower") or if previous scans failed due to rate limits.
             - Adjust `concurrency` (template concurrency) or `bulk_size` (host concurrency) if performance tuning is explicitly mentioned.
           - **Optimizations:**
             - Adjust `timeout` (default 10s) if requested or if timeouts occurred previously.
             - Use `retries` if network instability is suspected or requested.
             - Consider `stop_at_first_match: True` for quicker checks if the user only needs to know if *any* vulnerability exists, not all of them.
             - Use `scan_strategy` (e.g., `host-spray`) if the user specifies a preference.
           - **Headless Mode:**
             - Set `headless: True` if the user specifically asks for scans requiring browser interaction or mentions headless templates.
             - Adjust `page_timeout` if headless scans are timing out.
           - **Output & Debugging:**
             - Set `verbose: True` *only* if the user explicitly asks for verbose Nuclei output. The final `NetworkScanResult` should still be structured regardless.
             - Use `debug`, `debug_req`, `debug_resp` only for deep troubleshooting if requested.
             - Use `proxy` if a proxy URL is provided or required.
           - **General:**
             - Handle redirects (`follow_redirects`, `max_redirects`) based on context or explicit requests.
             - Pass custom `header` values if provided.

        3. Execute the `nuclei_scan_tool` with the determined parameters.
           - Interpret the nuclei scan results carefully.
           # Check the explicit scan_status field:
           - If `scan_status` is "error", note the error from the `error` field for later reporting.
           - If `scan_status` is "success_with_findings", proceed to analyze the `findings` list.
           - If `scan_status` is "success_no_findings", note this for reporting (Step 7).

        4. For each finding (if any), document:
           - Name of the vulnerability
           - Severity level
           - Description
           - Remediation steps (if available)
           - References and CVE IDs

        5. Create a summary of findings grouped by severity (if any).

        6. Provide actionable recommendations based on the findings (if any):
           - Prioritize critical and high severity issues
           - Suggest specific remediation steps
           - Recommend additional security measures if appropriate

        **IMPORTANT RECAP for Reporting:**
           - Before generating the final `NetworkScanResult`, double-check the tool output's `scan_status`.
           - If `scan_status` is "success_no_findings", this **IS NOT AN ERROR**. It means the scan ran correctly but found nothing with the current settings.
           - **DO NOT** invent errors, report tool problems, or mention flag issues when `scan_status` is "success_no_findings".

        7. Return a comprehensive NetworkScanResult containing all findings (if any),
           the summary, and your recommendations.
           - **Crucially:** If the scan result's `scan_status` is "success_no_findings", explicitly state this in the summary and recommendations (e.g., "Scan completed successfully. No vulnerabilities were detected with the current configuration and templates."). Ensure the `vulnerabilities` list is empty and the `summary` reflects zero counts.
           - If `scan_status` is "success_with_findings", populate the `vulnerabilities` list and `summary` counts accurately based on the findings.
           - If `scan_status` is "error", report the error clearly in the `scan_details` or `recommendations` based on the message noted in step 3.
           - If `scan_status` is "error", report the error clearly in the `scan_details` field based on the message noted in step 3.

        Remember that your analysis needs to be accurate, prioritized by risk,
        and actionable for security teams. Focus on providing clear, practical
        recommendations that help improve security posture.
        """
# fmt: on


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
            tools=[nuclei_scan_tool_instance, parse_domain_info_tool_instance],
        )

    @Agent.instructions
    def instruction(self) -> str:
        """Provide instructions for network security analysis."""
        # Return the constant prompt string
        return NETWORK_SECURITY_AGENT_PROMPT


# Define the standalone function that the CLI will call
async def scan_target(
    target: str,
    domain_info: Optional[Dict[str, Any]] = None,
    severity_filter: Optional[ScanSeverity] = None,
    rate_limit: int = 150,  # Add back rate_limit, maybe others if needed by CLI
    # Add other params corresponding to CLI options if necessary
) -> Optional[NetworkScanResult]:  # Return Optional for error handling
    """
    Scan a target for security vulnerabilities using the NetworkSecurityAgent.

    This function acts as a wrapper around the agent's run method,
    constructing the appropriate prompt and dependencies.

    Args:
        target: The target to scan (domain, IP, or URL)
        domain_info: Optional domain information from DomainAnalyzerAgent
        severity_filter: Optional filter for vulnerability severity
        rate_limit: Optional rate limit override (used in prompt construction)

    Returns:
        NetworkScanResult if scan successful, None otherwise.
    """
    # Instantiate the agent *inside* the function if it's not needed globally,
    # or ensure the global instance 'network_security_agent' is used correctly.
    agent_instance = NetworkSecurityAgent()  # Use a local instance or the global one

    try:
        deps = NetworkSecurityAgentDeps(domain_info=domain_info)

        # Construct the user prompt dynamically based on parameters
        user_prompt_parts = [f"Perform a comprehensive security scan of {target}."]
        if severity_filter:
            user_prompt_parts.append(
                f"Focus on {severity_filter.value} and higher severity issues."
            )
        # Include rate limit info in the prompt if it deviates from default, so agent knows
        if rate_limit != 150:
            user_prompt_parts.append(
                f"Adjust the scan rate limit towards {rate_limit} requests per second."
            )
        # Add more prompt parts based on other parameters if needed

        user_prompt = " ".join(user_prompt_parts)

        # Define usage limits if needed, potentially based on parameters
        usage_limits = UsageLimits(request_limit=30)  # Example limit

        result = await agent_instance.run(
            user_prompt, deps=deps, usage_limits=usage_limits
        )

        if isinstance(result.output, NetworkScanResult):
            return result.output
        else:
            # Log error: Agent returned unexpected type
            logger.error(
                f"Agent returned unexpected output type: {type(result.output)} "
                f"for target {target}"
            )
            return None  # Indicate failure

    except UsageLimitExceeded as e:
        logger.warning(f"Usage limit exceeded during network scan for {target}: {e}")
        return None
    except UnexpectedModelBehavior as e:
        # Catch errors where the model response was invalid or retries failed
        logger.exception(f"Model behavior error during network scan for {target}: {e}")
        return None
    except ModelHTTPError as e:
        # Catch specific HTTP errors from the model provider (e.g., 4xx, 5xx)
        logger.exception(f"Model HTTP error ({e.status_code}) for {target}: {e}")
        return None
    except AgentRunError as e:
        # Catch other Pydantic-AI specific runtime errors during the agent run
        logger.exception(f"Agent run error during network scan for {target}: {e}")
        return None
    except Exception as e:
        # Log the generic error properly before returning None
        logger.exception(
            f"Unexpected error during network scan execution for {target}: {e}"
        )
        return None  # Indicate failure


# Keep the global instance if other parts of the system need it directly
# Otherwise, it could be removed if only used via the scan_target wrapper.
network_security_agent = NetworkSecurityAgent()
