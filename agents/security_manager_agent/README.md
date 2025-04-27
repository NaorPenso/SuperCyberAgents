# Security Manager Agent (SuperCyberAgents)

This directory contains the implementation for the `security_manager_agent`.

## Purpose

This agent acts as an orchestrator or manager. It receives high-level security tasks,
uses its LLM to plan the necessary steps, delegates sub-tasks to specialized agents
(like `domain_whois_agent`) using the `delegate_task_tool`, and synthesizes the results
into a final summary.

## Configuration

Refer to `config/agents/security_manager_agent.yaml`.
Requires a capable LLM (e.g., GPT-4) for planning and delegation.
Must be configured to use the `delegate_task_tool`.

## Schemas

- **Input:** `SecurityManagerInput` (defined in `schemas/security_manager_schemas.py`)
- **Output:** `SecurityManagerOutput` (defined in `schemas/security_manager_schemas.py`)

## Tools Used

- `delegate_task_tool`: Used to execute other agents based on the manager's plan.

## Usage Notes

- Provide a clear, high-level task description in the input.
- Ensure all potential delegate agents are configured, running, and accessible. 