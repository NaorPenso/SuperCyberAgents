# Dockerfile (Alpine based)

# ---- Builder Stage ----
FROM python:3.11-alpine AS builder

# Install system dependencies for Poetry and potential build requirements
# build-base is needed for compiling extensions, curl for downloading poetry
RUN apk add --no-cache curl build-base

# Set environment variables for Poetry
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VERSION=1.8.3 \
    # Tell poetry to always create virtualenvs in .venv relative to pyproject.toml
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PATH="/opt/poetry/bin:$PATH"

WORKDIR /app

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -

# Copy dependency definition files
COPY pyproject.toml poetry.lock ./

# Install production dependencies
# This will create a .venv folder in /app
RUN poetry install --no-dev --no-root

# Copy the rest of the application code
COPY . .

# ---- Final Stage ----
FROM python:3.11-alpine AS final

# Set path env for poetry (though poetry itself isn't needed, venv path is)
ENV PATH="/opt/poetry/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install only necessary runtime dependencies (if any)
# Example: RUN apk add --no-cache libpq

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S -G appgroup appuser

# Copy virtual env from builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy application code from builder stage
# Ensure the target directory exists and has correct permissions beforehand
RUN mkdir -p /app && chown appuser:appgroup /app
COPY --from=builder --chown=appuser:appgroup /app /app

# Copy entrypoint script and make it executable
COPY --chown=appuser:appgroup entrypoint.sh .
RUN chmod +x ./entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port (for API mode)
EXPOSE 8000

# Set the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command can be empty, as entrypoint logic handles default mode
# Or set a default like CMD ["api"] or CMD ["cli"]
CMD [] 