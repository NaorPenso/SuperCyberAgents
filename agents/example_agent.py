"""Example Agent implementation."""

import logging

from agents import register_agent
from agents.base import AgentConfig, BaseAgent
from core.llm_clients import get_llm_client
from schemas.agent_schemas import ExampleAgentInput, ExampleAgentOutput
from schemas.tool_schemas import IPLookupInput, IPLookupOutput
from tools.base import BaseTool

logger = logging.getLogger(__name__)


@register_agent(name="example-agent")
class ExampleAgent(BaseAgent[ExampleAgentInput, ExampleAgentOutput]):
    """An example agent that analyzes security logs using an IP lookup tool."""

    input_schema = ExampleAgentInput
    output_schema = ExampleAgentOutput

    def __init__(self, config: AgentConfig, tools: list[BaseTool] | None = None):
        """Initialize with config and tools."""
        super().__init__(config, tools or [])
        # Get the LLM client instance based on config
        try:
            self.llm_client = get_llm_client(config.llm_provider)
        except ValueError as e:
            logger.error(
                f"Failed to get LLM client for provider '{config.llm_provider}': {e}"
            )
            # Decide how to handle: raise, disable agent, or use a fallback?
            # For now, let it raise to prevent agent from running without LLM.
            raise

    def run(self, input_data: ExampleAgentInput) -> ExampleAgentOutput:
        """Execute the agent's logic."""
        logger.info(
            f"Running ExampleAgent for log entry: {input_data.log_entry[:50]}..."
        )

        # 1. Analyze log entry with LLM
        prompt = f"Analyze the following security log entry and determine if it looks suspicious. Provide a brief summary.\n\nLog Entry: {input_data.log_entry}"
        try:
            llm_summary = self.llm_client.generate(
                prompt=prompt,
                model=self.config.model,
                **self.config.parameters,
            )
            logger.info("LLM analysis complete.")
        except Exception as e:
            logger.exception("LLM generation failed.")
            # Handle error appropriately - maybe return partial output or raise
            llm_summary = f"Error during LLM analysis: {e}"
            # Decide if agent should fail completely or proceed

        # 2. Use IP lookup tool if target IP exists and tool is configured
        ip_reputation_result = None
        if input_data.target_ip and "ip_lookup" in self.tools:
            ip_lookup_tool = self.tools["ip_lookup"]
            tool_input = IPLookupInput(ip_address=input_data.target_ip)
            try:
                logger.info(f"Executing ip_lookup tool for IP: {input_data.target_ip}")
                tool_output = ip_lookup_tool.execute(tool_input)
                if isinstance(tool_output, IPLookupOutput):
                    ip_reputation_result = tool_output.reputation
                    logger.info(f"IP Lookup result: {ip_reputation_result}")
                else:
                    logger.warning("IP lookup tool returned unexpected output type.")
            except Exception:
                logger.exception(
                    f"IP lookup tool execution failed for {input_data.target_ip}."
                )
                # Decide how to handle tool failure - continue or fail?

        # 3. Determine if suspicious (simple example logic)
        is_suspicious = False
        if (
            "error" in input_data.log_entry.lower()
            or "failed" in input_data.log_entry.lower()
        ):
            is_suspicious = True
        if ip_reputation_result and "malicious" in ip_reputation_result.lower():
            is_suspicious = True
        if "suspicious" in llm_summary.lower():  # Check LLM output too
            is_suspicious = True

        # 4. Construct and return output
        output = ExampleAgentOutput(
            analysis_summary=llm_summary,
            ip_reputation=ip_reputation_result,
            is_suspicious=is_suspicious,
        )
        logger.info(f"ExampleAgent finished processing. Suspicious: {is_suspicious}")
        return output
