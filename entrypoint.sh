#!/bin/sh
# entrypoint.sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Default mode is API if RUN_MODE is not set or empty
RUN_MODE=${RUN_MODE:-api}

echo "Container starting in '$RUN_MODE' mode..."

# Activate virtual environment (optional but good practice if scripts rely on it)
# source /app/.venv/bin/activate # This might not work depending on shell, direct execution is safer

# Execute based on RUN_MODE
if [ "$RUN_MODE" = "api" ]; then
    echo "Starting Uvicorn server for API..."
    # Execute Uvicorn using the Python from the virtualenv
    exec /app/.venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --log-config observability/logging_config.yaml
elif [ "$RUN_MODE" = "cli" ]; then
    echo "Starting CLI..."
    # Execute the CLI script using the Python from the virtualenv
    # Pass all arguments ($@) to the CLI script
    exec /app/.venv/bin/python cli/main.py "$@"
else
    echo "Error: Invalid RUN_MODE specified: '$RUN_MODE'. Use 'api' or 'cli'." >&2
    exit 1
fi 