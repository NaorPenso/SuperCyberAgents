"""Domain WHOIS Agent specialized in retrieving WHOIS information for domains.

This agent utilizes the whois_lookup_tool to gather registration and contact
details associated with a given domain name.
"""

import logging
from typing import List

# Remove unused imports like yaml, BaseModel (if not needed elsewhere)
from pydantic import ValidationError

# --- Adjust Base Agent Import Path --- #
# from ..base_agent import BaseAgent # Remove relative import
from agents import register_agent  # Import the decorator
from agents.base import AgentConfig, BaseAgent  # Import from project structure
from core.llm_clients import get_llm_client  # Import project's LLM client factory

# --- Import Schemas (will be defined later) --- #
from schemas.domain_whois_schemas import DomainWhoisInput, DomainWhoisOutput

# --- Adjust Tool Import Path --- #
# Assuming WhoisTool will be refactored into tools/whois_lookup_tool/
# from tools.whois_lookup.whois_tool import WhoisTool
from tools.base import BaseTool  # We'll likely need a SuperCyberAgent tool

# from utils.llm_utils import create_central_llm # Likely remove if LLM isn't used for complex logic


logger = logging.getLogger(__name__)


# Remove CrewAI-specific config models (replaced by AgentConfig)
# class LLMConfig(BaseModel): ...
# class FunctionCallingLLM(BaseModel): ...
# class FileAnalysisLimits(BaseModel): ...
# class SecurityContext(BaseModel): ...
# class domain_whois_agentConfig(BaseModel): ...


# --- Refactored DomainWhoisAgent --- #
@register_agent(name="domain_whois_agent")  # Add the registration decorator
class DomainWhoisAgent(
    BaseAgent[DomainWhoisInput, DomainWhoisOutput]
):  # Inherit from project's BaseAgent
    """Agent for retrieving and parsing WHOIS data for a domain."""

    # Class-level attributes (Can be kept if useful, but not strictly required by BaseAgent)
    # NAME: ClassVar[str] = "domain_whois_agent"
    # DESCRIPTION: ClassVar[str] = (
    #     "An agent that retrieves and structures WHOIS information for domains"
    # )

    # Schemas defined at class level for BaseAgent compatibility
    input_schema = DomainWhoisInput
    output_schema = DomainWhoisOutput

    def __init__(
        self, config: AgentConfig, tools: List[BaseTool]
    ):  # Use AgentConfig and project's BaseTool
        """Initialize the DomainWhoisAgent.

        Args:
            config: Agent configuration object.
            tools: List of initialized tool instances provided during system init.
        """
        # Call BaseAgent's __init__ to set config and tools dictionary
        super().__init__(config, tools)

        # Initialize LLM client using project's factory function
        try:
            self.llm_client = get_llm_client(config.llm_provider)
        except ValueError as e:
            logger.error(
                f"Failed to get LLM client for provider '{config.llm_provider}': {e}"
            )
            # Decide how to handle: raise, disable agent, or use a fallback?
            # For now, let it raise to prevent agent from running without LLM.
            raise

        # Store config and tools (already done by super().__init__)
        # self.config = config
        # self.tool_instances = {tool_ref.alias: tool for tool_ref, tool in zip(config.tools, tools)}

        logger.info(f"DomainWhoisAgent initialized with ID: {self.config.id}")

    # --- Remove CrewAI Specific Methods --- #
    # def _load_config(self, config_path: str) -> Optional[domain_whois_agentConfig]: ...
    # def get_agent(self) -> Agent: ...
    # def get_task_result(self, task: Any) -> Dict: ...

    # --- Implement the run method --- #
    def run(self, input_data: DomainWhoisInput) -> DomainWhoisOutput:
        """Retrieve and structure WHOIS information for the given domain."""
        logger.info(f"Running DomainWhoisAgent for domain: {input_data.domain}")

        whois_tool_alias = "whois_lookup"  # Define the expected alias for the tool
        whois_output = None
        error_message = None

        # 1. Check if the required tool is available
        if whois_tool_alias not in self.tools:
            error_message = (
                f"Required tool '{whois_tool_alias}' not found in agent configuration."
            )
            logger.error(error_message)
            # Return an error structure consistent with DomainWhoisOutput
            # This assumes DomainWhoisOutput can represent errors.
            # We might need a union or specific error fields later.
            return DomainWhoisOutput(domain_name=input_data.domain, error=error_message)

        whois_tool_instance = self.tools[whois_tool_alias]

        # 2. Prepare input for the WHOIS tool
        # Assuming the tool input schema requires a 'domain' field
        # We'll need to define WhoisLookupInput schema later.
        try:
            # This assumes WhoisLookupInput exists and takes a 'domain' field
            from schemas.whois_lookup_schemas import (
                WhoisLookupInput,
            )  # Define this later

            tool_input = WhoisLookupInput(domain=input_data.domain)
        except ValidationError as e:  # ImportError shouldn't happen if schemas exist
            error_message = f"Failed to prepare input for WHOIS tool: {e}"
            logger.exception(error_message)
            return DomainWhoisOutput(domain_name=input_data.domain, error=error_message)
        except Exception as e:
            # Catch other unexpected errors during input prep
            error_message = f"Unexpected error preparing input for WHOIS tool: {e}"
            logger.exception(error_message)
            return DomainWhoisOutput(domain_name=input_data.domain, error=error_message)

        # 3. Execute the WHOIS tool
        try:
            logger.info(f"Executing {whois_tool_alias} tool for {input_data.domain}")
            # Assuming the tool's execute method returns WhoisLookupOutput
            whois_output = whois_tool_instance.execute(tool_input)
            logger.info(f"WHOIS tool executed successfully for {input_data.domain}")

            # Check if the tool itself returned an error structure
            # Access the error attribute directly from the Pydantic model
            if whois_output.error:
                logger.warning(f"WHOIS tool returned error: {whois_output.error}")
                # Propagate the tool's error message
                return DomainWhoisOutput(
                    domain_name=input_data.domain,
                    error=whois_output.error,
                    raw_data=whois_output.raw_data,
                )

        except Exception as e:
            error_message = f"WHOIS tool execution failed: {e}"
            logger.exception(error_message)
            return DomainWhoisOutput(domain_name=input_data.domain, error=error_message)

        # 4. Process the WHOIS tool output
        # The original agent didn't seem to use LLM based on config/readme.
        # It just structured the output. We'll directly map the tool output
        # to the agent output schema.
        # This assumes WhoisLookupOutput has fields corresponding to DomainWhoisOutput.
        try:
            # Direct mapping (adjust fields as necessary based on actual schemas)
            output_data = DomainWhoisOutput(
                domain_name=getattr(whois_output, "domain_name", input_data.domain),
                registrar=getattr(whois_output, "registrar", None),
                creation_date=getattr(whois_output, "creation_date", None),
                expiration_date=getattr(whois_output, "expiration_date", None),
                name_servers=whois_output.name_servers,
                status=whois_output.status,
                emails=whois_output.emails,
                dnssec=getattr(whois_output, "dnssec", None),
                updated_date=getattr(whois_output, "updated_date", None),
                # Include raw data if available from the tool
                raw_data=whois_output.raw_data,
                error=None,  # Explicitly set error to None on success
            )
            logger.info(f"Successfully processed WHOIS data for {input_data.domain}")
            return output_data

        except Exception as e:
            error_message = f"Failed to process WHOIS tool output: {e}"
            logger.exception(error_message)
            return DomainWhoisOutput(
                domain_name=input_data.domain,
                raw_data=getattr(
                    whois_output, "raw_data", None
                ),  # Include raw data if available even on mapping error
                error=error_message,
            )
