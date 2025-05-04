# ruff: noqa: E501
"""Pydantic-AI Agent for performing comprehensive domain analysis."""

import asyncio
import logging
import os
from typing import Any, Type

# --- Python Standard Library --- #
# --- Third Party Imports --- #
from dotenv import load_dotenv
from pydantic_ai import Agent
from pydantic_ai.exceptions import (  # Model didn't behave as expected;; Specific HTTP errors from model provider;; Catch-all for unexpected LLM issues
    AgentRunError,  # Base class for agent run issues
    ModelHTTPError,
    UnexpectedModelBehavior,
    UsageLimitExceeded,
)
from pydantic_ai.usage import UsageLimits

# Project Imports
from schemas.domain_analysis import DomainAnalysisResult
from tools.domain_tools import (
    crt_sh_lookup,
    dns_security_check,
    email_security_check,
    ipwhois_lookup,
    shodan_host_lookup,
    virustotal_url_analysis,
)

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# fmt: off
DOMAIN_ANALYSIS_SYSTEM_PROMPT = """You are a Domain Analysis Agent.
 Your goal is to perform a comprehensive security and configuration analysis
 for a given domain. Follow these steps using the available tools:

1.  **IP Information:** Use the `ipwhois_lookup` tool to find the primary IP
    address associated with the domain and retrieve its WHOIS information (ASN,
    country, description).
2.  **Shodan Scan (If IP Found):** If an IP address was successfully resolved in step 1,
    use the `shodan_host_lookup` tool with that IP address to gather
    information about open ports, services, OS, organization, and potential
    vulnerabilities. **If step 1 failed to find an IP, skip this step.**
3.  **VirusTotal URL Check:** Use the `virustotal_url_analysis` tool with the
    original domain name to check its reputation and threat score based on the
    latest analysis report.
4.  **Certificate Analysis:** Use the `crt_sh_lookup` tool to find relevant
    SSL/TLS certificates associated with the domain. Extract key details like
    issuer, common names, and validity period for each certificate found.
5.  **DNS Security:** Use the `dns_security_check` tool to determine if DNSSEC
    is enabled and properly configured for the domain.
6.  **Email Security:** Use the `email_security_check` tool to retrieve and
    evaluate the domain's SPF and DMARC records. Determine the DMARC policy.
7.  **Synthesize Results:** Compile all collected information (IP details, Shodan
    scan results, VirusTotal analysis, certificate list, DNS security status,
    email security status) into the `DomainAnalysisResult` structure. Ensure the
    `shodan_info` and `vt_analysis` fields are populated if the respective scans
    were performed and returned data.
8.  **Summarize:** Based on the gathered data, write a concise
    `analysis_summary` highlighting the key findings, potential risks (including
    any high threat scores from VirusTotal or vulnerabilities from Shodan), or
    notable configurations for the domain.

Ensure all fields in the `DomainAnalysisResult` are populated accurately based
on the tool outputs. If a tool fails or returns no data for a section, reflect
that appropriately in the output (e.g., leaving optional fields as null or
noting the lack of data in the summary).

**Error Handling:** If any tool fails during execution (e.g., API error, timeout,
no data found), make a best effort to continue with the other steps. Note any
tool failures or lack of data for specific sections clearly in the final
`analysis_summary`.

**Consistency Check:** If results from different tools seem contradictory (e.g.,
VirusTotal clean, Shodan shows CVEs), briefly mention this potential discrepancy
in the `analysis_summary`.
"""
# fmt: on

# --- Configuration --- #
# Determine the LLM model string based on environment variables
DEFAULT_PROVIDER = "openai"
DEFAULT_MODEL_NAME = "o4-mini"  # Default model if specific one isn't set

# Get the primary provider (e.g., "openai", "google", etc.)
primary_provider = os.getenv("PRIMARY_LLM_PROVIDER", DEFAULT_PROVIDER).lower()

# Construct the model string (e.g., "openai:gpt-4o")
if primary_provider == "openai":
    model_name = os.getenv("OPENAI_MODEL_NAME", DEFAULT_MODEL_NAME)
    llm_model_string = f"openai:{model_name}"
# Add elif blocks here for other providers (e.g., google/gemini) if needed
# elif primary_provider == "google":
#     model_name = os.getenv("GOOGLE_MODEL_NAME", "gemini-1.5-flash-latest") # Example
#     llm_model_string = f"google:{model_name}"
else:
    # Fallback or handle unsupported provider
    logger.warning(
        f"Unsupported PRIMARY_LLM_PROVIDER: {primary_provider}. "
        f"Falling back to default OpenAI."
    )
    model_name = os.getenv("OPENAI_MODEL_NAME", DEFAULT_MODEL_NAME)
    llm_model_string = f"openai:{model_name}"


# Note: API keys (OPENAI_API_KEY, GOOGLE_API_KEY) and base URLs (OPENAI_API_BASE)
# are automatically read by Pydantic-AI providers from standard environment variables.

# --- Agent Definition --- #

# Define the detailed steps for the system prompt - MOVED TO CONSTANT ABOVE
# DOMAIN_ANALYSIS_SYSTEM_PROMPT = """ ... """

logger.info(f"Initializing DomainAnalyzerAgent with model: {llm_model_string}")

# Instantiate the agent. We specify the output type and register tools.
# Add the detailed instructions as a system prompt.
domain_analyzer_agent: Agent[
    Any, Type[DomainAnalysisResult]  # Use Any for deps if no deps_type is specified
] = Agent(
    model=llm_model_string,  # Use the constructed model string
    output_type=DomainAnalysisResult,
    system_prompt=DOMAIN_ANALYSIS_SYSTEM_PROMPT,  # Use the constant
    # Register tools directly. Pydantic-AI infers schema from type hints & docstrings.
    tools=[
        crt_sh_lookup,
        ipwhois_lookup,
        dns_security_check,
        email_security_check,
        shodan_host_lookup,
        virustotal_url_analysis,
    ],
)


# --- Agent Instructions Decorator --- #
# This decorator defines the input schema (domain: str) for the agent's task.
# The decorated function MUST return a string, even if minimal.
@domain_analyzer_agent.instructions
def generate_domain_analysis(domain: str) -> str:  # pragma: no cover
    """Entry point instruction for initiating domain analysis.

    Args:
        domain: The domain name to analyze.
    """
    # Pydantic-AI requires the instruction function to return a string.
    return f"Initiating analysis for domain: {domain}"


# --- Execution Wrapper (Optional but Recommended) ---
# Example of how you might wrap the agent execution
async def run_domain_analysis(domain_to_analyze: str) -> DomainAnalysisResult | None:
    """Runs the domain analysis agent for the given domain.

    Args:
        domain_to_analyze: The domain name to analyze.

    Returns:
        The DomainAnalysisResult if successful, None otherwise.
    """
    logger.info(f"Running domain analysis for: {domain_to_analyze}")
    try:
        # Temporarily remove token limit for debugging.
        # Set limit to None.
        usage_limits = UsageLimits(request_limit=150, total_tokens_limit=None)

        # The user prompt tells the agent WHAT domain to analyze.
        # The system prompt tells the agent HOW to analyze it.
        # The @agent.instructions tells the agent the FUNCTION SIGNATURE
        # to expect for this task.
        user_prompt = f"Analyze the domain: {domain_to_analyze}"

        result = await domain_analyzer_agent.run(
            user_prompt,  # Pass the specific task here
            usage_limits=usage_limits,
        )
        logger.info(f"Successfully completed analysis for {domain_to_analyze}")
        # Ensure the output matches the expected type
        if isinstance(result.output, DomainAnalysisResult):
            return result.output
        else:
            logger.error(
                f"Agent returned unexpected output type: {type(result.output)} "
                f"for {domain_to_analyze}"
            )
            return None
    except UsageLimitExceeded as e:
        logger.warning(
            f"Usage limit exceeded during analysis for {domain_to_analyze}: {e}"
        )
        return None
    except UnexpectedModelBehavior as e:
        # Catch errors where the model response was invalid or retries failed
        logger.exception(
            f"Model behavior error during domain analysis for {domain_to_analyze}: {e}"
        )
        return None
    except ModelHTTPError as e:
        # Catch specific HTTP errors from the model provider (e.g., 4xx, 5xx)
        logger.exception(
            f"Model HTTP error ({e.status_code}) for {domain_to_analyze}: {e}"
        )
        return None
    except AgentRunError as e:
        # Catch other Pydantic-AI specific runtime errors during the agent run
        logger.exception(
            f"Agent run error during domain analysis for {domain_to_analyze}: {e}"
        )
        return None
    except Exception as e:
        # Catch any other unexpected errors
        logger.exception(
            f"Unexpected error during domain analysis for {domain_to_analyze}: {e}"
        )
        return None


# Example of how to run it (e.g., for local testing)
if __name__ == "__main__":  # pragma: no cover
    test_domain = "google.com"  # Or get from command line args
    analysis = asyncio.run(run_domain_analysis(test_domain))
    if analysis:
        pass
    else:
        pass
