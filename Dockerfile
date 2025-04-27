# Dockerfile

# ---- Base Image ----
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PATH="/opt/poetry/bin:$PATH"

WORKDIR /app

# Install Poetry
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -sSL https://install.python-poetry.org | python - && \
    apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*

# ---- Builder Image ----
FROM base AS builder

# Install build dependencies (if any, e.g., for compiling C extensions)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copy project files and install dependencies
COPY pyproject.toml poetry.lock ./

# Install dependencies including dev dependencies needed for potential build steps
# Install only production dependencies without virtualenv, excluding dev groups
RUN poetry install --no-dev --no-root

# Copy the rest of the application code
COPY . .

# ---- Final Image ----
FROM base AS final

# Copy installed dependencies from builder stage
COPY --from=builder ${POETRY_HOME} ${POETRY_HOME}
COPY --from=builder /app/.venv /app/.venv

# Copy application code from builder stage
COPY --from=builder /app /app

# Create a non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser
WORKDIR /home/appuser/app # Change WORKDIR to user's home

# Expose port for FastAPI
EXPOSE 8000

# Default command to run the FastAPI server using the virtualenv Python
# Note: Adjust path if .venv is not directly under /app
CMD [".venv/bin/uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"] 