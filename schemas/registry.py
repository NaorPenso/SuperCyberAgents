"""Schema registry for dynamically accessing Pydantic models."""

import logging
from typing import Dict, Type

from pydantic import BaseModel

logger = logging.getLogger(__name__)

SCHEMA_REGISTRY: Dict[str, Type[BaseModel]] = {}


def register_schema(name: str):
    """Decorator to register a Pydantic schema class in the registry."""

    def decorator(cls: Type[BaseModel]):
        if not issubclass(cls, BaseModel):
            raise TypeError("Registered schema must be a Pydantic BaseModel.")
        if name in SCHEMA_REGISTRY:
            logger.warning(
                f"Schema '{name}' is already registered. Overwriting."
                f" Existing: {SCHEMA_REGISTRY[name]}, New: {cls}"
            )
        SCHEMA_REGISTRY[name] = cls
        logger.debug(f"Registered schema: '{name}' -> {cls.__name__}")
        return cls

    return decorator
