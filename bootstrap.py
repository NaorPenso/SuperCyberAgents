import os
import subprocess
import sys

# Project constants
PROJECT_NAME = "SuperCyberAgents"
PYTHON_VERSION = "3.13"

# Directories
DIRECTORIES = [
    "agents",
    "tools",
    "schemas",
    "config/agents",
    "config/tools",
    "api/routers",
    "cli",
    "observability",
    "tests",
    "docs",
    ".github/workflows",
    "helm/templates",
]


# Initialize directories
def create_directories():
    for directory in DIRECTORIES:
        os.makedirs(directory, exist_ok=True)


# Initialize poetry
def init_poetry():
    subprocess.run(
        [
            "poetry",
            "init",
            "-n",
            "--python",
            f">={PYTHON_VERSION}",
            "--name",
            PROJECT_NAME,
        ]
    )


# Add main and dev dependencies using Poetry
def add_dependencies():
    main_deps = [
        "fastapi",
        "typer",
        "pydantic",
        "pydantic-ai",
        "requests",
        "boto3",
        "pyyaml",
        "uvicorn",
        "logfire",
    ]
    dev_deps = ["black", "isort", "flake8", "pytest", "bandit"]

    subprocess.run(["poetry", "add", *main_deps])
    subprocess.run(["poetry", "add", "--group", "dev", *dev_deps])


# Configure pyproject.toml
def configure_pyproject():
    content = f"""
[tool.poetry]
name = \"{PROJECT_NAME}\"
version = \"0.1.0\"
description = \"Cybersecurity AI Agent System\"
authors = [\"Your Name <you@example.com>\"]

[tool.poetry.dependencies]
python = \">={PYTHON_VERSION}\"

[tool.black]
line-length = 88

[tool.isort]
profile = \"black\"

[tool.pytest.ini_options]
python_files = \"test_*.py\"
addopts = \"-ra -q\"
"""
    with open("pyproject.toml", "w") as f:
        f.write(content)


# Configure flake8
def configure_flake8():
    content = """
[flake8]
max-line-length = 88
ignore = E203, E266, E501, W503
exclude = .git,__pycache__,build,dist
"""
    with open(".flake8", "w") as f:
        f.write(content)


# Create Dockerfile
def create_dockerfile():
    content = f"""
FROM python:{PYTHON_VERSION}-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install poetry
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && poetry install --no-dev
COPY . .
CMD [\"uvicorn\", \"api.main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"80\"]
"""
    with open("Dockerfile", "w") as f:
        f.write(content)


# Create README.md
def create_readme():
    content = f"""
# {PROJECT_NAME}

## Setup
```bash
poetry install
poetry run uvicorn api.main:app --reload
```
"""
    with open("README.md", "w") as f:
        f.write(content)


# GitHub Actions workflow
def create_github_workflow():
    content = f"""
name: CI
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: \"{PYTHON_VERSION}\"
      - run: pip install poetry
      - run: poetry install
      - run: poetry run black --check .
      - run: poetry run isort --check-only .
      - run: poetry run flake8 .

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: \"{PYTHON_VERSION}\"
      - run: pip install poetry
      - run: poetry install
      - run: poetry run pytest

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: \"{PYTHON_VERSION}\"
      - run: pip install poetry
      - run: poetry install
      - run: poetry run bandit -r .
"""
    with open(".github/workflows/ci.yml", "w") as f:
        f.write(content)


# Main orchestration
def main():
    create_directories()
    init_poetry()
    add_dependencies()
    configure_pyproject()
    configure_flake8()
    create_dockerfile()
    create_readme()
    create_github_workflow()


if __name__ == "__main__":
    if sys.version_info < (3, 13):
        sys.exit(1)
    main()
