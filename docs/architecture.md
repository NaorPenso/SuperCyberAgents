# Architecture

This document outlines the software architecture for the SuperCyberAgents project, which is built using the Pydantic-AI framework.

## Overview

SuperCyberAgents implements a modular architecture where AI agents are defined using Pydantic-AI, a framework that provides type-safe integration with Large Language Models (LLMs). The system uses structured data models (Pydantic schemas) for agent input/output and offers both API and CLI interfaces.

## Key Components

### Agents (`agents/`)

AI agents defined using Pydantic-AI's `Agent` class. Each agent:
- Defines a specific task (e.g., domain analysis)
- Uses tools to accomplish its goal
- Produces structured outputs via Pydantic models
- Has a clear system prompt that describes its objective and process

Example: `DomainAnalyzerAgent` which performs security analysis of domains.

### Tools (`tools/`)

Reusable functions that agents can call to retrieve information or perform actions. Tools:
- Are registered with agents
- Have typed signatures with Pydantic models
- Return structured data
- Handle errors gracefully with proper logging

Example: `crt_sh_lookup`, `ipwhois_lookup`, `shodan_host_lookup`

### Schemas (`schemas/`)

Pydantic models that define structured data contracts throughout the system:
- Input/output schemas for agents
- Data models for API endpoints
- Response formats for tools

Example: `DomainAnalysisResult`, `ShodanHostInfo`, `VirusTotalUrlAnalysis`

### API (`api/`)

FastAPI application that provides HTTP endpoints for interacting with agents:
- RESTful interface
- Automatic OpenAPI documentation
- Dependency injection for shared resources
- Proper error handling and status codes

### CLI (`cli/`)

Typer-based command-line interface for direct interaction with agents:
- Commands for each agent's functionality
- Structured input/output
- Help text and documentation
- Error handling and logging

### Observability (`observability/`)

Logging and monitoring setup:
- JSON-formatted structured logging
- Configurable log levels
- Request tracing

### Core (`core/`)

Foundational components and initialization logic:
- System initialization
- Configuration loading
- Provider management

### Tests (`tests/`)

Comprehensive test suite:
- Unit tests for components
- Integration tests for agents
- Mocked LLM responses via Pydantic-AI testing utilities

## Data Flow

1. User request comes in via API or CLI
2. The appropriate agent is invoked with input parameters
3. The agent uses its tools to gather information
4. The agent synthesizes the gathered information into structured output
5. The response is returned to the user in the appropriate format

## Design Principles

- **Type Safety**: Using Pydantic models throughout for validation
- **Modularity**: Components are loosely coupled
- **Testability**: All components can be tested in isolation
- **Error Handling**: Graceful handling of errors at all levels
- **Documentation**: Clear documentation for code and interfaces

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