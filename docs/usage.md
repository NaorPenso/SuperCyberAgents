# Usage Guide

This guide explains how to use the API and CLI interfaces.

## API Usage

The API is served using FastAPI. See the main `README.md` for how to run it.

*   **Health Check:** `GET /health`
*   **List Agents:** `GET /agents/`
*   **Invoke Agent:** `POST /agents/{agent_id}/invoke`
    *   Body (JSON): `{"input": { ... }}` where `input` matches the agent's input schema.

Interactive documentation (Swagger UI) is available at `/docs` when the API is running.

## CLI Usage

See the main `README.md` for basic commands.

*   `poetry run python -m cli.main --help`
*   `poetry run python -m cli.main agent list`
*   `poetry run python -m cli.main agent run <agent_id> --input-file <path/to/input.json>`

## Adding New Agents/Tools

1.  Define YAML configuration in `config/agents/` or `config/tools/`.
2.  Define Pydantic input/output schemas in `schemas/`.
3.  Implement the agent/tool class in `agents/` or `tools/`, inheriting from `BaseAgent`/`BaseTool`.
4.  Register the class using the `@register_agent`/`@register_tool` decorator.
5.  Add unit tests in `tests/`. 