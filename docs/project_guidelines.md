# Project Guidelines and Coding Standards

This document consolidates all the key guidelines, rules, and coding standards for the SuperCyberAgents project. Adherence to these principles is mandatory to ensure consistency, maintainability, and quality.

---

## 1. Core Project Context (`project-context`)

*   **Project Name:** SuperCyberAgents
*   **Core Technology:** Python, Pydantic, **Pydantic-AI**, FastAPI (for API), Typer (for CLI), Logfire.
*   **Purpose:** Develop customizable AI agents for cybersecurity tasks using the Pydantic-AI framework.
*   **Development Focus:** Implementing agents with appropriate prompts/instructions, tools, dependencies, and structured outputs using Pydantic-AI.
*   **Mandatory Workflow:** Poetry MUST be used exclusively for dependency management (`pyproject.toml`) and running tests (`poetry run pytest`).
*   **Coding Standards:** Adhere strictly to `careful_coding` guidelines (clean code, meaningful names, DRY, SRP, etc.) and Flake8/Ruff rules.
*   **Critical Constraint:** Do NOT mention "Cursor" or specific AI tooling/rules in project code, documentation, commit messages, PRs, or issues.

### User's Business Objective

*   To **automate, augment, or streamline cybersecurity operations** by leveraging AI agents.
*   Goals include improving efficiency, speeding up analysis, automating tasks, enhancing team capabilities, and developing specialized AI agents for specific security domains.

---

## 2. Pydantic-AI Usage and Best Practices

This section outlines how to effectively use the Pydantic-AI framework within this project, based on its documentation.

### 2.1. Agent Definition

*   **Core Class:** Use [`pydantic_ai.Agent`][pydantic_ai.Agent] to define agents. Agents are the primary interface for LLM interaction.
*   **Components:** Agents encapsulate:
    *   Instructions or System Prompts
    *   Function Tools
    *   Structured Output Types
    *   Dependency Type Constraints
    *   Optional Default LLM Model and Settings
*   **Initialization:** Specify the LLM model (`'provider:model-name'`), [`deps_type`][pydantic_ai.Agent.__init__] (type of dependencies needed), and [`output_type`][pydantic_ai.Agent.__init__] (expected output structure).
*   **Instructions vs. System Prompts:**
    *   Use the `instructions` parameter or `@agent.instruction` decorator for prompts specific to the current agent run. **This is generally preferred.** Instructions from previous messages in a history are *not* resent.
    *   Use `system_prompt` parameter or `@agent.system_prompt` decorator if prompts from previous message history *need* to be retained in subsequent requests.
    *   Dynamic prompts (using `@agent.system_prompt` or `@agent.instruction` with a function taking `RunContext`) allow runtime information (like dependencies) to be injected.
*   **Reusability:** Instantiate agents once (often as module globals) and reuse them throughout the application, similar to FastAPI Apps or Routers. They are designed to be stateless containers for configuration and tools.
*   **Configuration:** Agent behavior (prompts, tools, output types) is primarily defined in Python code, not separate configuration files. API keys and provider endpoints should be managed via environment variables (see `config/providers.yaml` for structure, but keys are sourced from env).
*   **Type Safety:** Agents are generic (`Agent[DepsType, OutputType]`), enabling static type checking for dependencies and outputs.

### 2.2. Function Tool Definition

*   **Purpose:** Provide mechanisms for agents to retrieve external information or perform actions, augmenting the LLM's capabilities (similar to the 'R' in RAG).
*   **Registration:**
    *   Use [`@agent.tool`][pydantic_ai.Agent.tool] for tools needing access to agent context/dependencies via [`RunContext`][pydantic_ai.tools.RunContext]. **This is the default/most common way.**
    *   Use [`@agent.tool_plain`][pydantic_ai.Agent.tool_plain] for simpler tools without context needs.
    *   Alternatively, register plain functions or [`Tool`][pydantic_ai.tools.Tool] instances via the `tools` list in the `Agent` constructor for reusability or finer control.
*   **Schema Generation:** Pydantic-AI automatically generates JSON schemas for tools based on:
    *   Function parameter type hints (excluding `RunContext`).
    *   Docstrings (including parameter descriptions in Google, Numpy, or Sphinx format). Use `docstring_format` and `require_parameter_descriptions` arguments in decorators/`Tool` for control.
    *   If a tool has a single object-like parameter (Pydantic model, TypedDict, dataclass), its schema is used directly for the tool.
*   **Return Types:** Tools can return various types; PydanticAI handles serialization (often to JSON) if the model expects text.
*   **Common Tools:** Utilize pre-built tools like [`duckduckgo_search_tool`][pydantic_ai.common_tools.duckduckgo.duckduckgo_search_tool] or [`tavily_search_tool`][pydantic_ai.common_tools.tavily.tavily_search_tool] when appropriate (requires installing optional dependencies like `pydantic-ai-slim[duckduckgo]` or `pydantic-ai-slim[tavily]`).
*   **Dynamic Tools:** Use the `prepare` argument with a [`ToolPrepareFunc`][pydantic_ai.tools.ToolPrepareFunc] (taking `RunContext` and `ToolDefinition`) to dynamically modify the tool's schema or omit the tool entirely for a specific step based on runtime context.

### 2.3. Output Handling

*   **Output Definition:** Specify the agent's expected final output structure using the `output_type` argument in the `Agent` constructor. This determines what the agent aims to produce at the end of a run.
*   **Structured Output:**
    *   If `output_type` is *not* `str` (e.g., Pydantic model, `TypedDict`, `list`, `int`), Pydantic-AI registers it as a tool for the LLM to call. This ensures the final output conforms to the specified schema.
    *   Pydantic validates the data returned by the LLM against this schema.
    *   Unions (excluding `str`) register each member as a separate potential output tool.
    *   Non-object schemas (e.g., `int`, `list[str]`) are wrapped in a single-element object schema for the underlying tool representation.
*   **Plain Text Output:** If `output_type` is `str` (or a `Union` including `str`), the agent can return plain text directly from the LLM without a final tool call.
*   **Output Validation:** Use [`@agent.output_validator`][pydantic_ai.Agent.output_validator] for complex, potentially async validation logic that runs *after* Pydantic validation. Access `RunContext` here if needed. Validators can raise [`ModelRetry`][pydantic_ai.exceptions.ModelRetry] to ask the LLM to correct the output.

### 2.4. Running Agents & Control Flow

*   **Execution Methods:**
    *   `agent.run()`: Async, returns full [`AgentRunResult`][pydantic_ai.agent.AgentRunResult] upon completion.
    *   `agent.run_sync()`: Sync wrapper for `run()`.
    *   `agent.run_stream()`: Async, returns [`StreamedRunResult`][pydantic_ai.result.StreamedRunResult] context manager for streaming.
    *   `agent.iter()`: Async context manager returning [`AgentRun`][pydantic_ai.agent.AgentRun] for fine-grained, node-by-node iteration over the agent's underlying execution graph (powered by `pydantic-graph`). Useful for deep inspection or injecting custom logic.
*   **Core Flow:** An agent run typically involves:
    1.  Processing User Input + System Prompts/Instructions.
    2.  Sending a `ModelRequest` to the LLM.
    3.  Receiving a `ModelResponse` which might contain text or tool calls.
    4.  If tool calls: Executing the corresponding function tools.
    5.  Sending `ToolReturnPart` messages back in a new `ModelRequest`.
    6.  Repeating steps 3-5 until the LLM provides a final text output (if `str` is allowed) or calls the structured output tool.
*   **Dependencies:** Pass required dependencies (matching `deps_type`) via the `deps` argument during the `run*` call.
*   **Message History:** Maintain conversation context by passing messages from previous results via `message_history=result.new_messages()` or `result.all_messages()`.
*   **Streaming:**
    *   Use `StreamedRunResult.stream_text()` for text output (optionally `delta=True`).
    *   Use `StreamedRunResult.stream()` or `StreamedRunResult.stream_structured()` / `validate_structured_output()` for structured data, leveraging Pydantic's partial validation (best with `TypedDict`).
*   **Usage Limits:** Control costs and prevent loops using [`UsageLimits`][pydantic_ai.usage.UsageLimits] (`request_limit`, `*_tokens_limit`) passed to `run*` methods.
*   **Model Settings:** Fine-tune LLM behavior (e.g., `temperature`, `max_tokens`, provider-specific settings like `gemini_safety_settings`) by passing [`ModelSettings`][pydantic_ai.settings.ModelSettings] to `run*` methods or the `Agent` constructor.

### 2.5. Dependencies (`deps_type` & `RunContext`)

*   **Definition:** Specify the type of dependencies an agent and its tools require using `deps_type` in the `Agent` constructor (e.g., `DatabaseConnection`, a dataclass containing multiple resources).
*   **Access:** Tools decorated with `@agent.tool` and validators with `@agent.output_validator` receive a [`RunContext[YourDepsType]`][pydantic_ai.tools.RunContext] argument. Access dependencies via `ctx.deps`.
*   **Passing:** Provide the actual dependency object(s) during `agent.run*` calls using the `deps=` argument. Ensure the passed object matches `deps_type`.

### 2.6. Error Handling & Retries

*   **Model Retry:** Tools or output validators can raise [`ModelRetry(reason)`][pydantic_ai.exceptions.ModelRetry] to signal that the LLM's tool call arguments or generated output were invalid and ask it to try again with the provided `reason`. Configure default retries on the `Agent` or per-tool/validator. Access the current attempt number via `ctx.retry`.
*   **Model Errors:** Expect and handle [`UnexpectedModelBehavior`][pydantic_ai.exceptions.UnexpectedModelBehavior] for issues like exceeding max retries, LLM API errors (e.g., 503, rate limits), or content safety violations.
*   **Debugging:** Use the [`capture_run_messages`][pydantic_ai.capture_run_messages] context manager to inspect the full sequence of [`ModelMessage`][pydantic_ai.messages.ModelMessage]s (`ModelRequest`, `ModelResponse`) exchanged during a failed (or successful) run.

### 2.7. Testing Strategy

*   **Framework:** Use `pytest` with `pytest-asyncio` for async code.
*   **Isolate from LLMs:** Unit tests **must not** call real LLM APIs. Set `pydantic_ai.models.ALLOW_MODEL_REQUESTS = False` globally in test setups (e.g., `conftest.py` or test modules).
*   **Mocking Models:**
    *   Use [`TestModel`][pydantic_ai.models.test.TestModel] for simple scenarios. It simulates tool calls and generates *syntactically valid* data based on tool/output schemas but doesn't understand semantics. Configure its behavior (e.g., `custom_output_text`, specific tool return values) as needed.
    *   Use [`FunctionModel`][pydantic_ai.models.function.FunctionModel] for complex tests requiring control over the LLM's simulated responses (tool calls, final output) based on the message history. Pass a function (`Callable[[list[ModelMessage], AgentInfo], ModelResponse]`) that mimics LLM logic.
*   **Applying Mocks:** Use the [`Agent.override(model=...)`][pydantic_ai.agent.Agent.override] context manager within tests (or via pytest fixtures) to replace the agent's production model with `TestModel` or `FunctionModel` without altering the application code that calls the agent.
*   **Assertions:**
    *   Verify the final `result.output`.
    *   Use [`capture_run_messages`][pydantic_ai.capture_run_messages] to assert the sequence and content of messages (`ModelRequest`, `ModelResponse`, `ToolCallPart`, `ToolReturnPart`, etc.) to ensure the agent interacted with the (mocked) model as expected.
    *   Use libraries like `dirty-equals` for flexible assertions involving changing values like timestamps (`IsNow`) or IDs (`IsStr`).

### 2.8. Multi-Agent Application Patterns

*   **Agent Delegation:** An agent (parent) calls another agent (delegate) from within one of its tools (`@agent.tool`).
    *   Pass `ctx.usage` from the parent's `RunContext` to the delegate agent's run (`usage=ctx.usage`) to track cumulative usage correctly.
    *   Pass dependencies from the parent if the delegate needs them (`deps=ctx.deps`). The delegate's `deps_type` should generally be compatible with (or a subset of) the parent's.
*   **Programmatic Hand-off:** Application logic orchestrates calls to different agents sequentially. Useful for distinct phases of a workflow or incorporating human-in-the-loop steps.
    *   Maintain the overall conversation state (`message_history`) and cumulative usage (`Usage` object) across calls to different agents.
*   **Graph-Based Control Flow (Advanced):** For highly complex workflows with conditional branching, loops, and state management beyond simple sequences, consider using `pydantic-graph` directly to define a state machine where nodes can execute specific agents or logic. Pydantic-AI uses `pydantic-graph` internally (`agent.iter()` exposes this).

---

## 3. Python & FastAPI Development (`ai-python-fast-api`)

You are an expert in Python, FastAPI, and scalable API development.

### Key Principles

*   Write concise, technical responses with accurate Python examples.
*   Use functional, declarative programming; avoid classes where possible (though Pydantic-AI Agents are classes, tools and helpers should often be functions).
*   Prefer iteration and modularization over code duplication.
*   Use descriptive variable names with auxiliary verbs (e.g., `is_active`, `has_permission`).
*   Use lowercase with underscores for directories and files (e.g., `routers/user_routes.py`).
*   Favor named exports for routes and utility functions.
*   Use the Receive an Object, Return an Object (RORO) pattern for API endpoints and tool functions where applicable.

### Python/FastAPI Specifics

*   Use `def` for pure functions and `async def` for asynchronous operations (Pydantic-AI agent runs and many tools will be `async`).
*   Use type hints for all function signatures. Pydantic models (or `TypedDict`) are essential for Pydantic-AI `output_type` and tool parameters.
*   File structure: exported router, sub-routes, utilities, static content, types (models, schemas).
*   Follow standard Python style for conditionals.

### Error Handling and Validation

*   Prioritize error handling and edge cases:
    *   Handle errors/edge cases early in functions (guard clauses).
    *   Use early returns for errors.
    *   Place happy path last.
    *   Use `if-return` pattern over `else`.
    *   Implement proper logging (JSON format configured in `observability/logging.py`).
    *   Use custom error types or factories if needed.

### Dependencies

*   FastAPI
*   Pydantic v2 (Core for Pydantic-AI)
*   Pydantic-AI
*   Async libraries (`httpx` used in tests, `asyncio` for core operations)

### FastAPI-Specific Guidelines

*   Use functional components (plain functions) and Pydantic models for input validation and response schemas in API routes.
*   Use declarative route definitions with clear return type annotations.
*   Use `def` for synchronous API operations and `async def` for asynchronous ones (most agent interactions will be async).
*   Minimize `@app.on_event`; use lifespan context managers (as currently implemented in `api/main.py`).
*   Use middleware for logging, error monitoring, etc.
*   Optimize for performance using `async` for I/O (agent calls, tool I/O), consider caching where appropriate.
*   Use `HTTPException` for expected API errors. Map specific Pydantic-AI or application errors to appropriate HTTP statuses if needed.
*   Use middleware for handling unexpected errors.
*   Use Pydantic `BaseModel` for API request/response validation.

### Performance Optimization

*   Minimize blocking I/O; use async operations for agent runs, tool I/O (API calls, DB access).
*   Consider caching strategies if applicable (e.g., caching tool results, agent responses for identical inputs).
*   Leverage Pydantic for efficient serialization/deserialization.

### Key Conventions

1.  Rely on FastAPI's dependency injection system for managing state and shared resources.
2.  Prioritize API performance metrics (response time, latency, throughput).
3.  Limit blocking operations in routes; agent runs should be `await`-ed. Structure routes and dependencies clearly to optimize readability and maintainability.

*Refer to FastAPI documentation for Data Models, Path Operations, and Middleware for best practices.*

---

## 4. Clean Code Guidelines (`careful_coding`)

Guidelines for writing clean, maintainable, and human-readable code. Apply these rules when writing or reviewing code to ensure consistency and quality.

*   **Constants Over Magic Numbers:**
    *   Replace hard-coded values with named constants.
    *   Use descriptive constant names that explain the value's purpose.
    *   Keep constants at the top of the file or in a dedicated constants file.
*   **Meaningful Names:**
    *   Variables, functions, classes, agents, tools should reveal their purpose.
    *   Names should explain why something exists and how it's used.
    *   Avoid abbreviations unless they're universally understood.
*   **Smart Comments:**
    *   Don't comment *what*, comment *why*. Document APIs, complex logic, non-obvious Pydantic-AI interactions.
    *   Use comments to explain *why* something is done a certain way.
    *   Document APIs, complex algorithms, and non-obvious side effects.
*   **Single Responsibility Principle (SRP):**
    *   Each function/tool should do one thing. Agents should have focused goals.
    *   Functions should be small and focused.
    *   If a function needs a comment to explain what it does, it should be split.
*   **DRY (Don't Repeat Yourself):**
    *   Extract repeated code/logic into reusable functions/tools.
    *   Share common logic through proper abstraction.
    *   Maintain single sources of truth.
*   **Clean Structure:**
    *   Keep related code together (agents, tools, schemas).
    *   Organize code in a logical hierarchy.
    *   Use consistent file and folder naming conventions.
*   **Encapsulation:**
    *   Hide implementation details within tools/agents where appropriate.
    *   Expose clear interfaces.
    *   Move nested conditionals into well-named functions.
*   **Code Quality Maintenance:**
    *   Refactor continuously.
    *   Fix technical debt early.
    *   Leave code cleaner than you found it.
*   **Testing:**
    *   Write tests (`pytest`) for agents and tools using Pydantic-AI testing utilities.
    *   Keep tests readable and maintainable.
    *   Test edge cases and error conditions.
*   **Version Control:**
    *   Write clear commit messages.
    *   Make small, focused commits.
    *   Use meaningful branch names.

---

## 5. General Coding Principles (`coding_principles`)

*   **Preserve existing functionality:** Validate changes against current behavior to ensure no regression.
*   **Maintain data integrity:** Verify no critical code or data loss during any operation.
*   **Document all changes:** Ensure documentation reflects modifications.
*   **Follow DRY principle:** Avoid code duplication through proper abstraction and centralization.
*   **Maintain KISS principle:** Keep implementations simple and avoid unnecessary complexity.
*   **Apply YAGNI principle:** Only implement features when needed, avoid speculative development.
*   **Code for maintainability:** Document non-obvious decisions.
*   **Follow least astonishment:** Maintain consistent patterns and predictable behavior.

---

## 6. Flake8/Ruff Style Enforcement

You MUST ensure all Python code you generate, modify, or suggest **strictly adheres** to the Flake8/Ruff linting rules as configured in this project (`pyproject.toml`). Non-compliance is unacceptable.

Always refer to the `pyproject.toml` for the specific Flake8/Ruff configuration, including ignored rules (`ignore = [...]`) or selected rules (`select = [...]`).

### Key Directive Example:

*   **Line Length (E501):** **Strictly enforce a maximum line length of 88 characters.** Never generate or suggest code exceeding this limit.

### Core Flake8 Violations to Enforce (Non-Exhaustive):

Actively check for and prevent **all** violations reported by the configured linters (Flake8/Ruff). This includes, but is not limited to:

*   **Pycodestyle Errors (E***) and Warnings (W***):** Enforce PEP 8 style regarding indentation, whitespace, blank lines, imports, line length (max 88 chars), and statements (e.g., avoid `E722` bare `except:`).
*   **Pyflakes Errors (F***):** Prevent logical errors like unused imports (`F401`), undefined names (`F821`), unused variables (`F841`), issues with control flow (`F7xx`), and incorrect syntax/runtime issues (`F5xx-F9xx`).
*   **McCabe Complexity (C901):** Generate and refactor code to stay below the complexity threshold defined in `pyproject.toml`. Break down complex logic into smaller functions.

### Handling Rule Violations (`# noqa`):

*   **Do not add `# noqa: CODE` comments unless explicitly instructed and justified.**
*   If reviewing code, flag `# noqa` comments lacking clear justification. Project-wide ignores belong *only* in `pyproject.toml`.

---

## 7. Poetry Dependency & Test Management (`poetry-dependencies`)

*   **Core Requirement:** You MUST ALWAYS use Poetry for managing dependencies and running tests.
*   **NEVER** use pip, pipenv, or other package managers directly.
*   **NEVER** use pytest directly without Poetry.

### Command Guidelines

*   Install: `poetry install`
*   Add: `poetry add [package-name]`
*   Run tests: `poetry run pytest [options]`
*   Update: `poetry update`
*   Run scripts: `poetry run python script.py`

### Project Configuration

*   Dependencies declared in `pyproject.toml`.
*   Dev dependencies in appropriate groups.
*   Test configs in `[tool.pytest.ini_options]`.
*   Always use the Poetry virtual environment. 