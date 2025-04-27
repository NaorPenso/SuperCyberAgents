# Architecture

This document outlines the software architecture for the Cybersecurity AI Agent System.

(Details based on the initial prompt should be added here.)

Key components:

*   **Agents (`agents/`)**: Core logic units.
*   **Tools (`tools/`)**: Reusable capabilities.
*   **Schemas (`schemas/`)**: Pydantic data models.
*   **Configuration (`config/`)**: YAML files for agents, tools, providers.
*   **API (`api/`)**: FastAPI interface.
*   **CLI (`cli/`)**: Typer interface.
*   **Observability (`observability/`)**: Logging setup.
*   **Providers (`providers/`)**: LLM provider abstractions.
*   **Core (`core/`)**: Initialization and registry logic.
*   **Tests (`tests/`)**: Unit and integration tests.
*   **CI/CD (`.github/workflows/`)**: Automation pipelines.
*   **Containerization (`Dockerfile`)**: Docker build definition.
*   **Deployment (`helm/`)**: Kubernetes Helm chart. 