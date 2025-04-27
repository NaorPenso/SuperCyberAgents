"""Main FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager

import logfire
from dotenv import load_dotenv
from fastapi import FastAPI

# Moved imports to the top
from api.routers import agents as agents_router
from core.initialization import initialize_system
from observability.logging import setup_logging

# Load environment variables first
load_dotenv()

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events (startup/shutdown)."""
    # Startup
    # Use logger once configured
    setup_logging()
    logger.info("Starting up Cyber AI Agent API...")
    try:
        logfire.configure()
        # logfire_settings = InstrumentationSettings() # F841: Removed unused variable
        logfire.instrument_httpx(capture_all=True)
        # Agent instrumentation is now handled within BaseAgent.__init__
        logger.info("Logfire configured. HTTPX and Logging instrumented.")
        initialize_system()
        logger.info("System initialized successfully.")
    except Exception:
        # Use logger here as it should be configured by now
        logger.exception("System initialization failed during startup.")
        # Optional: print for critical startup failure visibility if logging fails
        # print(f"ERROR: Failed to configure Logfire or initialize system: {e}")
    yield
    # Shutdown
    logger.info("Shutting down Cyber AI Agent API...")
    # logger.info("Application shutdown.") # Duplicate log message


app = FastAPI(
    title="SuperCyberAgents API",
    description="API for managing and interacting with AI-powered cybersecurity agents.",
    version="0.1.0",
    lifespan=lifespan,
)

# Include agent routes
app.include_router(agents_router.router, prefix="/agents", tags=["Agents"])


@app.get("/", tags=["Status"])
async def read_root():
    """Root endpoint for basic API status check."""
    return {"status": "SuperCyberAgents API is running"}


# Example of how to run (if needed for local dev)
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)
