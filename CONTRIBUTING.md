# Contributing to SuperCyberAgents

Thank you for your interest in contributing to SuperCyberAgents! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to foster an inclusive and positive community.

## Getting Started

1. Fork the repository
2. Clone your forked repository locally
3. Install dependencies with Poetry: `poetry install`
4. Create a new branch for your changes: `git checkout -b feature/your-feature-name`

## Development Environment

This project uses Poetry for dependency management and follows strict coding standards:

- Use `poetry run ruff check .` to check linting
- Ensure tests pass with `poetry run pytest`
- Maintain test coverage above 80% (ideally 95%+)

## Pull Request Process

1. Ensure your code follows the project's coding standards
2. Update documentation as necessary
3. Add or update tests for your changes
4. Ensure all tests pass
5. Create a pull request with a clear description of your changes
6. Fill out the pull request template completely

## Coding Standards

This project strictly adheres to the pydantic-ai-constitution, which includes:

- PydanticAI-Centric design: All agent logic uses `pydantic_ai.Agent`
- Type Safety: Use explicit Python type hints and Pydantic models
- Async operations: Use `async def` for I/O-bound operations
- Code organization: Follow the established folder structure
- Naming conventions:
  - Classes: PascalCase (`DomainAnalyzerAgent`)
  - Functions: snake_case (`analyze_domain`)
  - Constants: UPPER_SNAKE_CASE (`DEFAULT_TIMEOUT`)
  - Files: snake_case (`domain_analyzer_agent.py`)

## Testing

- All new functionality must include tests
- Tests should be deterministic with fixed seeds/mocks
- Use `pytest` for all testing
- Use Pydantic-AI testing utilities like `TestModel` for agent tests

## Documentation

- Update documentation for all user-facing changes
- Keep code comments focused on "why" rather than "what"
- Use docstrings for all public functions and classes
- Follow Google-style docstring format

## Submitting Features

For major changes or new features:

1. First open an issue describing the proposed changes
2. Discuss the implementation approach
3. Implement the changes on a feature branch
4. Submit a pull request referencing the issue

## Reporting Bugs

When reporting bugs, please include:

- A clear description of the issue
- Steps to reproduce
- Expected vs. actual behavior
- Version information
- Any relevant logs or error messages

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License. 