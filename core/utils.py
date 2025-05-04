"""Core utility functions."""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def extract_domain(url_or_domain: str) -> str | None:
    """Extract domain from URL/domain string.

    Handles basic cases including adding missing schemes for parsing.
    Returns None if extraction is unreliable.
    """
    try:
        input_str = url_or_domain
        if "//" not in input_str:
            # Avoid adding http:// if it looks like just a domain (no path chars)
            if "/" not in input_str:
                input_str = f"http://{input_str}"
            else:
                # It has path characters but no scheme, cannot reliably parse
                logger.debug(f"Cannot reliably parse {url_or_domain} without scheme.")
                return None

        parsed = urlparse(input_str)
        domain = parsed.netloc

        # Handle cases like 'domain.com/path' where netloc might be empty
        # if scheme wasn't added properly.
        if (
            not domain
            and "//" not in url_or_domain
            and "/" not in url_or_domain
            and "." in url_or_domain
        ):
            # If no netloc AND original had no scheme/path, treat original as domain
            domain = url_or_domain

        if not domain:
            logger.debug(f"Could not parse netloc from {input_str}")
            return None  # Cannot reliably extract domain

        # Remove port if present
        domain = domain.split(":")[0]

        # Final check: Does it look like a domain? (Contains a dot)
        return domain if "." in domain else None
    except Exception as e:
        logger.exception(f"Error extracting domain from {url_or_domain}: {e}")
        return None
