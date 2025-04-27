"""Tool for performing WHOIS lookups on domain names."""

import logging
from datetime import datetime
from typing import Any, List, Optional

# Attempt to import the whois library
try:
    import whois
except ImportError:
    whois = None
    logging.warning(
        "'python-whois' library not found. WHOIS tool will not function. "
        "Install with: poetry add python-whois"
    )


from agents.base import ToolConfig
from schemas.whois_lookup_schemas import WhoisLookupInput, WhoisLookupOutput
from tools import register_tool
from tools.base import BaseTool

logger = logging.getLogger(__name__)


def _normalize_value(value: Any) -> Any:
    """Helper to normalize WHOIS data types (e.g., list or single value)."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]  # Return single item if it's a list of one
    return value


def _ensure_list(value: Any) -> List[Any]:
    """Ensure the value is a list."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Safely parse datetime, handling single values or lists."""
    dt_val = _normalize_value(value)
    if isinstance(dt_val, datetime):
        return dt_val
    # Add more parsing logic if needed, though python-whois often returns datetime objects
    return None


@register_tool(name="whois_lookup_tool")
class WhoisLookupTool(BaseTool[WhoisLookupInput, WhoisLookupOutput]):
    """Performs a WHOIS lookup for a given domain name."""

    input_schema = WhoisLookupInput
    output_schema = WhoisLookupOutput

    def __init__(self, config: ToolConfig):
        super().__init__(config)

    def execute(self, input_data: WhoisLookupInput) -> WhoisLookupOutput:
        """Execute the WHOIS lookup."""
        if whois is None:
            return WhoisLookupOutput(
                error="WHOIS library (python-whois) is not installed."
            )

        domain = input_data.domain
        logger.info(f"Performing WHOIS lookup for domain: {domain}")

        try:
            w = whois.whois(domain)

            # Check if the response indicates domain not found or other issues
            # python-whois might return a mostly empty object or specific statuses
            if not w.domain_name and not w.registrar:
                # Basic check, might need refinement based on library behavior
                logger.warning(
                    f"WHOIS lookup for {domain} returned no significant data."
                )
                return WhoisLookupOutput(
                    domain_name=domain,
                    error=f"Domain '{domain}' not found or WHOIS data incomplete.",
                )

            # Map fields, handling potential lists vs single values from whois lib
            output = WhoisLookupOutput(
                domain_name=(
                    str(_normalize_value(w.domain_name)) if w.domain_name else domain
                ),
                registrar=str(_normalize_value(w.registrar)) if w.registrar else None,
                creation_date=_parse_datetime(w.creation_date),
                expiration_date=_parse_datetime(w.expiration_date),
                name_servers=_ensure_list(w.name_servers),
                status=_ensure_list(w.status),
                emails=_ensure_list(w.emails),
                dnssec=str(_normalize_value(w.dnssec)) if w.dnssec else None,
                updated_date=_parse_datetime(w.updated_date),
                raw_data=w.text if hasattr(w, "text") else None,
                error=None,
            )
            logger.info(f"WHOIS lookup successful for {domain}")
            return output

        except whois.exceptions.WhoisCommandFailed as e:
            error_message = f"WHOIS command failed: {e}"
            logger.error(error_message)
            return WhoisLookupOutput(domain_name=domain, error=error_message)
        except whois.exceptions.WhoisRateLimitError as e:
            error_message = f"WHOIS rate limit exceeded: {e}"
            logger.error(error_message)
            return WhoisLookupOutput(domain_name=domain, error=error_message)
        except Exception as e:
            # Catch potential exceptions from the whois library or parsing
            error_message = f"Error during WHOIS lookup for {domain}: {e}"
            logger.exception(error_message)
            return WhoisLookupOutput(domain_name=domain, error=error_message)
