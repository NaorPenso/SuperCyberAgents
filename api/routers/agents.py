"""API Routers for Pydantic-AI agent interactions.

Placeholder - endpoints will be added as agents are implemented.
"""

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter()

# TODO: Add endpoints for Pydantic-AI agents as they are created.

# Placeholder for potential future initialization if needed
# def initialize_system():
#     pass


@router.get("/")
async def get_agents_root():
    """Root endpoint for the agents router."""
    return {"message": "Agent router is active"}
