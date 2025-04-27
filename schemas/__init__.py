"""Expose schema registry and registration decorator."""

from .registry import SCHEMA_REGISTRY, register_schema

__all__ = ["SCHEMA_REGISTRY", "register_schema"]
