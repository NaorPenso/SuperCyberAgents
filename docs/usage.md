# Usage Guide

This guide explains how to use the SuperCyberAgents project through its API and CLI interfaces.

## API Usage

The API is served using FastAPI and provides a clean interface for interacting with the AI agents.

### Running the API

```bash
poetry run uvicorn api.main:app --reload
```

The API will be available at `http://127.0.0.1:8000` with interactive Swagger documentation at `/docs`.

### API Endpoints

- **Health Check:** `GET /health`
  - Returns system health status
  
- **Domain Analysis:** `POST /domain/analyze`
  - Performs comprehensive security analysis of a domain
  - Request Body: `{"domain": "example.com"}`
  - Returns structured information about the domain's security posture

## CLI Usage

The CLI provides a command-line interface to the same functionality, using Typer.

### Basic Commands

View available commands:

```bash
poetry run python -m typer cli.main run --help
```

Get system information:

```bash
poetry run python -m typer cli.main run info
```

### Domain Analysis

Analyze a domain for security information:

```bash
poetry run python -m typer cli.main run analyze-domain example.com
```

This will return a JSON representation of the domain analysis results, including:
- IP WHOIS information
- SSL/TLS certificate details
- DNS security configuration (DNSSEC)
- Email security setup (SPF, DMARC)
- Shodan scan results (if IP is found)
- VirusTotal threat intelligence

### Setting Log Levels

You can control logging verbosity with the `--log-level` option:

```bash
poetry run python -m typer cli.main run --log-level DEBUG analyze-domain example.com
```

Valid log levels are: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

## Environment Configuration

The system requires certain environment variables for full functionality:

```
# Required for LLM functionality
PRIMARY_LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_key_here
OPENAI_MODEL_NAME=o4-mini

# Optional for specific tool functionality
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

These can be set in a `.env` file in the project root or exported in your shell environment.

## Creating New Agents

To create a new agent using the Pydantic-AI framework:

1. Define a new agent file in the `agents/` directory
2. Define necessary Pydantic schemas in `schemas/`
3. Create the agent using the `pydantic_ai.Agent` class
4. Register any needed tools with the agent
5. Add appropriate tests in `tests/agents/`
6. Update API and CLI interfaces to expose the new agent

Example of a minimal agent definition:

```python
from pydantic_ai import Agent
from schemas.my_schemas import MyOutputSchema
from tools.my_tools import my_tool_function

my_agent = Agent(
    model="openai:gpt-4o",
    output_type=MyOutputSchema,
    tools=[my_tool_function]
)

@my_agent.instructions
def generate_instructions(input_param: str) -> str:
    return f"Process this input: {input_param}"
```

## Error Handling

Both the API and CLI handle errors gracefully:

- API returns appropriate HTTP status codes with error details
- CLI provides readable error messages and exits with non-zero status codes
- All errors are logged for troubleshooting 