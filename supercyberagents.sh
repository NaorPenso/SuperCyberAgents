#!/bin/bash

# Script to run a SuperCyberAgent using Poetry
# Usage: ./supercyberagents.sh [agent_id] [input_file_path]
# Usage: ./supercyberagents.sh

# ASCII Art Banner
echo ""
echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗"
echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝"
echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗"
echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║"
echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║"
echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝"
echo ""

# Default values (if needed, e.g., default agent or input)
# DEFAULT_AGENT="example-agent"
# DEFAULT_INPUT="inputs/example_input.json"

# --- Argument Parsing --- #

# Agent ID is always the security manager
AGENT_ID="security_manager"

# Prompt for the task description
echo ""
read -p "Enter the task description for the Security Manager: " TASK_DESCRIPTION
if [ -z "$TASK_DESCRIPTION" ]; then
    echo "No task description provided. Exiting."
    exit 1
fi

# Construct the JSON input string for SecurityManagerInput
# Use printf for safer formatting, escaping potential special chars in TASK_DESCRIPTION
# Note: This simple printf might not handle complex nested quotes perfectly.
JSON_INPUT=$(printf '{ "task_description": "%s" }' "$TASK_DESCRIPTION")

# --- Execution --- #

echo "Running SuperCyberAgent System with:"
echo "Agent ID: $AGENT_ID"
# echo "Input Task: $TASK_DESCRIPTION" # Optional: echo the task
echo ""

# Ensure dependencies are installed (optional, but good practice)
# echo "Checking/installing dependencies..." # Removed - manage deps outside script
# poetry install --no-root --sync
# INSTALL_EXIT_CODE=$?
# if [ $INSTALL_EXIT_CODE -ne 0 ]; then
#     echo "Error during dependency installation. Exiting."
#     exit $INSTALL_EXIT_CODE
# fi
# echo "Dependencies checked."

# Run the agent using the project's CLI
echo "Executing agent..."
poetry run python -m cli.main agent run "$AGENT_ID" --input-json "$JSON_INPUT"

# Make script exit with the same code as the python command
exit $? 