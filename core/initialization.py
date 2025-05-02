"""Core initialization logic for the system."""

import logging

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# --- Initialization State --- #
_INITIALIZED = False


# --- Initialization Function --- #
def initialize_system():
    """Initialize core system components if needed.

    Currently, this function only ensures environment variables are loaded
    via `load_dotenv()` at the module level and logs an initialization message.
    No specific component initialization steps are performed here at this time.
    """
    global _INITIALIZED  # Declare intent to modify module-level variable

    # This check prevents redundant logging if called multiple times,
    # but true idempotency might require more state if initialization
    # becomes complex later.
    if _INITIALIZED:
        logger.debug("Initialization function already called.")
        return

    logger.info("Running system initialization checks...")
    try:
        # No specific initialization steps currently needed beyond dotenv load.
        _INITIALIZED = True  # Set the module-level flag
        logger.info("System initialization checks complete.")
    except Exception:
        logger.exception("System initialization check failed.")
        # Reset flag on failure
        _INITIALIZED = False
        raise
