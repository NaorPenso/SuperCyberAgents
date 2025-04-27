# Delegate Task Tool

This directory contains the implementation for the `delegate_task_tool`.

## Purpose

This tool allows a manager agent (like `security_manager_agent`) to delegate a specific task to another registered agent within the system.
It takes the target agent's ID and the input data for that agent, executes the target agent, and returns its result or any errors encountered.

## Configuration

Refer to `config/tools/delegate_task_tool.yaml`.
This tool currently does not have specific configuration options beyond the standard ones.

## Schemas

Input/Output schemas (`DelegateTaskInput`, `DelegateTaskOutput`) are defined in `schemas/delegate_task_schemas.py`.

## Usage Notes

- This tool relies on the `core.initialization` module to find and load agent instances and schemas.
- It attempts to validate the provided input against the target agent's specific input schema before execution.
- Errors during agent lookup, input validation, or agent execution are captured and returned in the output.
- **Important:** Currently, passing `RunContext` (for usage tracking) from the calling agent through this tool to the delegate agent is complex and not directly implemented. Usage for delegated tasks might not be fully aggregated under the parent agent's run. 