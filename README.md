# SuperCyberAgents

A modern cybersecurity toolkit built with Pydantic-AI that provides specialized AI agents for various security analysis tasks. This project enables security professionals to leverage LLM-powered agents for comprehensive domain analysis, threat intelligence, and security assessment.

## Key Features

- **Domain Analysis Agent:** Performs comprehensive security analysis of domains, examining certificates, DNS configuration, email security, IP information, Shodan data, and VirusTotal threat analysis.
- **High Test Coverage:** Maintains >95% test coverage to ensure reliability
- **Modern Architecture:** Built on Pydantic-AI for type-safe agent development
- **API and CLI Interfaces:** Interact with agents through a FastAPI server or command-line interface

## Architecture Overview

The project follows a clean architecture with:

- **Agents:** Defined in `agents/` using Pydantic-AI
- **Tools:** Reusable components that agents use for specific tasks
- **Schemas:** Pydantic models that define data structures and validation
- **API:** FastAPI-based web interface
- **CLI:** Typer-based command-line interface

## Setup

1. **Install Poetry:** [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)
2. **Clone the repository:** `git clone https://github.com/NaorPenso/SuperCyberAgents.git`
3. **Navigate to the project directory:** `cd SuperCyberAgents`
4. **Install dependencies:** `poetry install`
5. **Set up environment variables:** Create a `.env` file with necessary API keys:

```
# Required for LLM functionality
PRIMARY_LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_key_here
OPENAI_MODEL_NAME=o4-mini

# Optional for specific tool functionality
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

## Using the API

Start the API server:

```bash
poetry run uvicorn api.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`. Interactive documentation (Swagger UI) is at `http://127.0.0.1:8000/docs`.

## Using the CLI

View available commands:

```bash
poetry run python -m typer cli.main run --help
```

Run domain analysis:

```bash
poetry run python -m typer cli.main run analyze-domain example.com
```

Get system information:

```bash
poetry run python -m typer cli.main run info
```

## Testing

Run the test suite:

```bash
poetry run pytest
```

Check test coverage:

```bash
poetry run pytest --cov=.
```

## Linting and Formatting

```bash
# Check formatting and linting
poetry run ruff check .

# Apply automatic fixes
poetry run ruff check . --fix
```

## Example Usage

### Domain Analysis

The `analyze-domain` command provides a comprehensive security analysis of a domain:

```bash
poetry run python -m typer cli.main run analyze-domain example.com
```

This returns information about:
- IP and WHOIS data
- SSL/TLS certificates
- DNS security (DNSSEC)
- Email security (SPF, DMARC)
- Shodan scan results
- VirusTotal threat analysis

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.