"""Example Tool implementation: IP Lookup."""

import logging
import os

import requests
from pydantic import SecretStr

from agents.base import ToolConfig
from schemas.tool_schemas import IPLookupInput, IPLookupOutput
from tools import register_tool
from tools.base import BaseTool

logger = logging.getLogger(__name__)


@register_tool(name="ip_lookup_tool")
class IPLookupTool(BaseTool[IPLookupInput, IPLookupOutput]):
    """Tool to look up IP reputation from a threat intel API."""

    input_schema = IPLookupInput
    output_schema = IPLookupOutput

    def __init__(self, config: ToolConfig):
        super().__init__(config)
        self.api_url = "https://ipinfo.io/{ip}/json"

    def _get_api_key(self) -> SecretStr | None:
        """Retrieve API key from environment variable securely."""
        # Example: Expect API key in an environment variable like IP_LOOKUP_API_KEY
        api_key = os.getenv("IP_LOOKUP_API_KEY")
        return SecretStr(api_key) if api_key else None

    def execute(self, input_data: IPLookupInput) -> IPLookupOutput:
        """Execute the IP lookup API call."""
        if not self.config.endpoint:
            logger.error("IPLookupTool requires 'endpoint' in its configuration.")
            # Return a default error state or raise an exception
            return IPLookupOutput(
                ip_address=str(input_data.ip_address),
                reputation="error",
                details={"error": "Tool endpoint not configured"},
            )

        headers = {}
        if self.config.auth_required:
            api_key = self._get_api_key()
            if not api_key:
                logger.error(
                    "IPLookupTool requires auth, but IP_LOOKUP_API_KEY env var not set."
                )
                return IPLookupOutput(
                    ip_address=str(input_data.ip_address),
                    reputation="error",
                    details={"error": "API key not configured"},
                )
            # Example: Assume API key is passed in Authorization header
            headers["Authorization"] = f"Bearer {api_key.get_secret_value()}"

        url = self.config.endpoint
        params = {"ip": str(input_data.ip_address)}
        timeout = self.config.timeout_sec or 10  # Default timeout if not set

        try:
            logger.info(f"Calling IP lookup API: {url} for IP {input_data.ip_address}")
            response = requests.get(
                url, params=params, headers=headers, timeout=timeout
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            logger.info(f"IP lookup API response received for {input_data.ip_address}")

            # Adapt based on actual API response structure
            reputation = data.get("reputation", "unknown")
            details = data.get("details", {})

            return IPLookupOutput(
                ip_address=str(input_data.ip_address),
                reputation=reputation,
                details=details,
            )

        except requests.exceptions.RequestException as e:
            logger.exception(f"IP lookup API call failed: {e}")
            return IPLookupOutput(
                ip_address=str(input_data.ip_address),
                reputation="error",
                details={"error": f"API request failed: {e}"},
            )
        except Exception as e:
            logger.exception(f"Error processing IP lookup result: {e}")
            return IPLookupOutput(
                ip_address=str(input_data.ip_address),
                reputation="error",
                details={"error": f"Processing failed: {e}"},
            )
