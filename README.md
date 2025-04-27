# Cybersecurity AI Agent System

This project implements a system for building and running AI agents for cybersecurity tasks, based on the Pydantic AI framework.

## Architecture Overview

(Refer to `docs/architecture.md` for details)

## Setup

1.  **Install Poetry:** [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)
2.  **Clone the repository:** `git clone <repository-url>`
3.  **Navigate to the project directory:** `cd cyber-ai-agent`
4.  **Install dependencies:** `poetry install --all-extras` (or specify extras like `aws`, `logfire` if needed)
5.  **Set up environment variables:** Create a `.env` file (or export variables) for necessary API keys (e.g., `OPENAI_API_KEY`, `AZURE_OPENAI_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `LOGFIRE_API_KEY`). Refer to `config/providers.yaml` for expected variables.

## Running the API

```bash
poetry run uvicorn api.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`. Interactive documentation (Swagger UI) is at `http://127.0.0.1:8000/docs`.

## Running the CLI

```bash
poetry run python -m cli.main --help

# Example: List agents
poetry run python -m cli.main agent list

# Example: Run an agent (assuming input.json exists)
poetry run python -m cli.main agent run example-agent --input-file path/to/input.json
```

(Refer to `docs/usage.md` for more details)

## Testing

```bash
poetry run pytest
```

## Linting and Formatting

```bash
# Check formatting and linting
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy .
poetry run bandit -r .
poetry run yamllint .

# Apply formatting
poetry run ruff format .
```

## Building the Docker Image

```bash
docker build -t cyber-ai-agent:latest .
```

## Deployment (Kubernetes using Helm)

Refer to the `helm/` directory and `README.md` inside it for instructions.