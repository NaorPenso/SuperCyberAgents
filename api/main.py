"""Main FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager
from typing import Dict

# import logfire # Removed logfire import
from dotenv import load_dotenv
from fastapi import FastAPI

# Moved imports to the top
from api.routers import agents as agents_router
from core.initialization import initialize_system
from observability.logging import setup_logging

# Load environment variables first
load_dotenv()

logger = logging.getLogger(__name__)

# Removed Logfire configuration section
# logfire = Logfire(...)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events (startup/shutdown)."""
    # Startup
    setup_logging()
    logger.info("Starting up Cyber AI Agent API...")
    try:
        # Removed Logfire configure/instrument calls
        # logfire.configure()
        # logfire.instrument_httpx(capture_all=True)
        logger.info("Performing system initialization...")  # Updated log message
        initialize_system()
        logger.info("System initialized successfully.")
    except Exception:
        logger.exception("System initialization failed during startup.")
    yield
    # Shutdown
    logger.info("Shutting down Cyber AI Agent API...")


app = FastAPI(
    title="SuperCyberAgents API",
    description="API for interacting with cybersecurity AI agents.",
    version="0.1.0",
    lifespan=lifespan,
)

# Include agent routes
app.include_router(agents_router.router, prefix="/agents", tags=["Agents"])


# Health Check Endpoint
@app.get("/health", status_code=200, tags=["Health"], response_model=Dict[str, str])
async def health_check():
    """Basic health check endpoint."""
    return {"status": "ok"}


@app.get("/", tags=["Status"])
async def read_root():
    """Root endpoint for basic API status check."""
    return {"status": "SuperCyberAgents API is running"}


# Example of how to run (if needed for local dev)
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)
