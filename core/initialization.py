"""Core initialization logic for agents, tools, and providers."""

import importlib
import logging
import os
import pkgutil
from typing import Any, Dict, List

import yaml
from dotenv import load_dotenv  # Import load_dotenv
from pydantic import BaseModel, ValidationError

# --- Move all project-specific imports to the top --- #
import agents
import tools
import schemas
from schemas.registry import SCHEMA_REGISTRY
from agents import AGENT_REGISTRY
from agents.base import ToolConfig  # Import ToolConfig from agents.base
from agents.base import AgentConfig, BaseAgent
from providers.llm import (BedrockProvider, CerebrasProvider, LLMProvider,
                           OpenAIProvider)
from tools import TOOL_REGISTRY
from tools.base import BaseTool

# --- End moved imports --- #

# Load environment variables early, *after* all standard/library imports
load_dotenv()

logger = logging.getLogger(__name__)

# --- Global Registries & State (initialized by initialize_system) ---
_LOADED_PROVIDERS: Dict[str, LLMProvider] = {}
_LOADED_AGENTS: Dict[str, BaseAgent] = {}
_LOADED_TOOLS: Dict[str, BaseTool] = {}
_INITIALIZED = False


# --- Helper Functions ---


def _load_yaml_config(path: str) -> Any:
    """Load YAML configuration file."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # Changed severity: This might be expected if config is optional
        logger.debug(f"Configuration file not found: {path}")
        return None
    except yaml.YAMLError as e:
        logger.exception(f"Error parsing YAML file {path}: {e}")
        return None


def _import_modules(package: Any):
    """Dynamically import all modules in a package to run decorators."""
    if hasattr(package, "__path__"):
        # Use walk_packages to recursively find modules
        for _module_finder, name, _ispkg in pkgutil.walk_packages(
            package.__path__, package.__name__ + "."
        ):
            try:
                importlib.import_module(name)
                logger.debug(f"Successfully imported module: {name}")
            except Exception as e:
                logger.exception(f"Failed to import module {name}: {e}")
    else:
        logger.warning(f"Package {package.__name__} does not have __path__.")


def _initialize_providers():
    """Load LLM provider configurations and initialize clients conditionally."""
    global _LOADED_PROVIDERS
    _LOADED_PROVIDERS = {}  # Reset on initialization
    provider_config_data = _load_yaml_config("config/providers.yaml") or {}
    primary_provider_from_env = os.getenv("PRIMARY_LLM_PROVIDER", "").lower()

    logger.info(
        f"Primary LLM Provider from env: '{primary_provider_from_env if primary_provider_from_env else 'Not Set'}'"
    )
    logger.debug(f"Provider config file contents: {provider_config_data}")

    # Map provider keys to their initialization functions
    provider_map = {
        "openai": lambda cfg: OpenAIProvider(cfg, "openai"),
        "azure_openai": lambda cfg: OpenAIProvider(cfg, "azure_openai"),
        "aws_bedrock": BedrockProvider,
        "cerebras": CerebrasProvider,
    }

    for key, init_func in provider_map.items():
        should_load = False
        config_for_provider = provider_config_data.get(key)

        if config_for_provider is not None:
            logger.debug(f"Provider '{key}' found in config file.")
            should_load = True
        elif key == primary_provider_from_env:
            logger.debug(f"Provider '{key}' matches PRIMARY_LLM_PROVIDER env var.")
            should_load = True
            # If primary provider not in config, pass empty dict or handle None based on constructor
            config_for_provider = {}
        else:
            logger.debug(f"Skipping provider '{key}': Not in config and not primary.")

        if should_load:
            try:
                # Ensure config is a dict if expected by the constructor, handle None/str cases
                if not isinstance(config_for_provider, dict):
                    if config_for_provider is None:
                        config_for_provider = {}
                    else:
                        # Handle cases like bedrock where config might be just a region string
                        # This specific case needs provider-specific handling or better config structure
                        # For now, we'll assume constructors handle None or expect dicts
                        logger.warning(
                            f"Config for provider '{key}' is not a dictionary, passing empty dict. Actual config: {config_for_provider}"
                        )
                        config_for_provider = {}

                provider_instance = init_func(config_for_provider)
                _LOADED_PROVIDERS[key] = provider_instance
                logger.info(f"LLM Provider '{key}' loaded successfully.")
            except (ValueError, ImportError, AttributeError, TypeError, Exception) as e:
                # Catch broader errors including potential config issues (like AttributeError for bedrock)
                logger.error(
                    f"Failed to initialize provider '{key}': {e}. Provider disabled.",
                    exc_info=True,
                )
    logger.info(f"Loaded {len(_LOADED_PROVIDERS)} LLM providers.")


def _load_and_register_tools():
    """Discover, load, validate, and instantiate tools."""
    global _LOADED_TOOLS
    _LOADED_TOOLS = {}  # Reset on initialization
    _import_modules(tools)  # Ensure tool registration decorators run
    logger.info(f"Found {len(TOOL_REGISTRY)} registered tool classes.")

    config_tool_dir = "config/tools"
    if not os.path.isdir(config_tool_dir):
        logger.warning(f"Tool configuration directory not found: {config_tool_dir}")
        return

    for filename in os.listdir(config_tool_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            tool_config_path = os.path.join(config_tool_dir, filename)
            tool_config_data = _load_yaml_config(tool_config_path)
            if not tool_config_data:
                continue

            try:
                # Validate config structure first
                tool_cfg = ToolConfig(**tool_config_data)
            except ValidationError as e:
                logger.error(f"Invalid tool configuration in {filename}: {e}")
                continue

            # Find the registered tool class
            tool_class = TOOL_REGISTRY.get(tool_cfg.name)
            if not tool_class:
                logger.warning(
                    f"Tool '{tool_cfg.name}' defined in {filename} but no matching class registered. Skipping."
                )
                continue

            # Instantiate the tool
            try:
                tool_instance = tool_class(tool_cfg)
                _LOADED_TOOLS[tool_cfg.name] = tool_instance
                logger.info(f"Tool '{tool_cfg.name}' loaded successfully.")
            except Exception as e:
                logger.exception(
                    f"Failed to instantiate tool '{tool_cfg.name}' from {filename}: {e}"
                )
    logger.info(f"Loaded {len(_LOADED_TOOLS)} tool instances.")


def _resolve_agent_llm_provider(agent_cfg: AgentConfig) -> str | None:
    """Determine the LLM provider for an agent, falling back to environment variable."""
    provider_key = agent_cfg.llm_provider
    if not provider_key:
        provider_key = os.getenv("PRIMARY_LLM_PROVIDER")
        if provider_key:
            logger.info(
                f"Agent '{agent_cfg.id}': Using default provider from PRIMARY_LLM_PROVIDER: {provider_key}"
            )
        else:
            logger.error(
                f"Agent '{agent_cfg.id}': Missing LLM provider. Set llm_provider in config or PRIMARY_LLM_PROVIDER env var. Agent disabled."
            )
            return None

    # Normalize and update config object in-place
    resolved_provider = provider_key.lower()
    agent_cfg.llm_provider = resolved_provider
    logger.debug(f"Agent '{agent_cfg.id}': Resolved provider to '{resolved_provider}'")
    return resolved_provider


def _get_required_tool_instances(agent_cfg: AgentConfig) -> List[BaseTool] | None:
    """Get the instantiated tool objects required by the agent config."""
    agent_tools_instances = []
    for tool_ref in agent_cfg.tools:
        tool_instance = _LOADED_TOOLS.get(tool_ref.name)
        if not tool_instance:
            logger.error(
                f"Agent '{agent_cfg.id}' requires tool '{tool_ref.name}', but it was not loaded or failed to initialize. Agent disabled."
            )
            return None  # Indicate failure
        agent_tools_instances.append(tool_instance)
    return agent_tools_instances


def _resolve_agent_schemas(agent_cfg: AgentConfig) -> tuple[type[BaseModel] | None, type[BaseModel] | None]:
    """Resolves and returns the input and output schema classes for an agent using the registry."""
    input_schema_class = None
    output_schema_class = None

    # Look up input schema in the registry
    input_schema_name = agent_cfg.input_schema
    input_schema_class = SCHEMA_REGISTRY.get(input_schema_name)
    if input_schema_class:
        logger.debug(f"Resolved input schema '{input_schema_name}' from registry.")
    else:
        logger.error(
            f"Agent '{agent_cfg.id}': Failed to resolve input schema class '{input_schema_name}' from registry. "
            f"Ensure the schema is defined and decorated with @register_schema('{input_schema_name}'). Agent disabled."
        )
        # Still try to resolve output schema

    # Look up output schema in the registry
    output_schema_name = agent_cfg.output_schema
    output_schema_class = SCHEMA_REGISTRY.get(output_schema_name)
    if output_schema_class:
        logger.debug(f"Resolved output schema '{output_schema_name}' from registry.")
    else:
        logger.error(
            f"Agent '{agent_cfg.id}': Failed to resolve output schema class '{output_schema_name}' from registry. "
            f"Ensure the schema is defined and decorated with @register_schema('{output_schema_name}'). Agent disabled."
        )
        # Input schema might have resolved, but output failed

    # Return resolved classes (could be None if resolution failed)
    return input_schema_class, output_schema_class


def _instantiate_agent_from_config(
    agent_cfg: AgentConfig, filename: str
) -> BaseAgent | None:
    """Handles the instantiation logic for a single agent configuration."""
    if not agent_cfg.enabled:
        logger.info(
            f"Agent '{agent_cfg.id}' is disabled via config '{filename}'. Skipping."
        )
        return None

    # Find the registered agent class
    agent_class = AGENT_REGISTRY.get(agent_cfg.id)
    if not agent_class:
        logger.warning(
            f"Agent '{agent_cfg.id}' defined in {filename} but no matching class registered. Skipping."
        )
        return None

    # Resolve LLM provider and check if it's loaded
    resolved_provider = _resolve_agent_llm_provider(agent_cfg)
    if not resolved_provider:
        return None  # Error logged in helper
    if resolved_provider not in _LOADED_PROVIDERS:
        logger.error(
            f"Agent '{agent_cfg.id}' requires LLM provider '{resolved_provider}', which failed to load or is not configured. Agent disabled."
        )
        return None

    # Resolve and gather required tool instances
    agent_tools_instances = _get_required_tool_instances(agent_cfg)
    if agent_tools_instances is None:
        return None  # Error logged in helper

    # Resolve input/output schema classes (but don't assign to agent_cfg)
    input_schema_cls, output_schema_cls = _resolve_agent_schemas(agent_cfg)
    if not input_schema_cls or not output_schema_cls:
        logger.error(
            f"Agent '{agent_cfg.id}': Failed to resolve necessary schemas. Agent disabled."
        )
        return None  # Error logged in helper

    # Instantiate the agent
    # Note: BaseAgent constructor might need adjustment if it expects resolved schema classes
    # Currently, it likely relies on the schema names in the config.
    try:
        agent_instance = agent_class(config=agent_cfg, tools=agent_tools_instances)
        # Assign the resolved schema classes to the agent instance
        agent_instance.input_schema_class = input_schema_cls
        agent_instance.output_schema_class = output_schema_cls
        logger.info(f"Agent '{agent_cfg.id}' validated and ready.")
        return agent_instance
    except Exception as e:
        logger.exception(
            f"Failed to instantiate agent '{agent_cfg.id}' from {filename}: {e}"
        )
        return None


def _load_and_register_agents():
    """Discover agent classes, load configs, and instantiate agents."""
    global _LOADED_AGENTS
    _LOADED_AGENTS = {}  # Reset on initialization
    _import_modules(agents)  # Ensure agent registration decorators run
    logger.info(f"Found {len(AGENT_REGISTRY)} registered agent classes.")

    config_agent_dir = "config/agents"
    if not os.path.isdir(config_agent_dir):
        logger.warning(f"Agent configuration directory not found: {config_agent_dir}")
        return

    for filename in os.listdir(config_agent_dir):
        if not (filename.endswith(".yaml") or filename.endswith(".yml")):
            continue

        agent_config_path = os.path.join(config_agent_dir, filename)
        agent_config_data = _load_yaml_config(agent_config_path)
        if not agent_config_data:
            logger.warning(f"Skipping empty or invalid config file: {filename}")
            continue

        try:
            # Validate config structure first
            agent_cfg = AgentConfig(**agent_config_data)
        except ValidationError as e:
            logger.error(f"Invalid agent configuration structure in {filename}: {e}")
            continue

        # Delegate instantiation logic to helper function
        agent_instance = _instantiate_agent_from_config(agent_cfg, filename)

        if agent_instance:
            _LOADED_AGENTS[agent_cfg.id] = agent_instance
        # Errors during instantiation are logged within the helper

    logger.info(f"Loaded {len(_LOADED_AGENTS)} agent instances successfully.")


# --- Main Initialization Function ---


def initialize_system():
    """Initialize all components: providers, tools, agents. Idempotent."""
    global _INITIALIZED
    if _INITIALIZED:
        logger.debug("System already initialized. Skipping.")
        return

    logger.info("Starting system initialization...")

    # Order matters: Schemas -> Providers -> Tools -> Agents
    _import_modules(schemas) # Import all schema modules to populate registry
    _initialize_providers()
    _load_and_register_tools()
    _load_and_register_agents()

    _INITIALIZED = True
    logger.info("System initialization complete.")


# --- Accessor Functions ---


def get_llm_client(provider_key: str) -> LLMProvider:
    """Get an initialized LLM provider client by key."""
    if not _INITIALIZED:
        initialize_system()  # Ensure initialization runs if accessed early
    client = _LOADED_PROVIDERS.get(provider_key.lower())  # Normalize key on lookup
    if not client:
        raise ValueError(
            f"LLM provider '{provider_key}' is not configured, loaded, or failed to initialize."
        )
    return client


def get_agent(agent_id: str) -> BaseAgent | None:
    """Get a loaded agent instance by its ID."""
    if not _INITIALIZED:
        initialize_system()
    return _LOADED_AGENTS.get(agent_id)


def get_all_agents() -> Dict[str, BaseAgent]:
    """Get a dictionary of all loaded agent instances."""
    if not _INITIALIZED:
        initialize_system()
    return _LOADED_AGENTS.copy()  # Return a copy


def get_tool(tool_name: str) -> BaseTool | None:
    """Get a loaded tool instance by its name."""
    if not _INITIALIZED:
        initialize_system()
    return _LOADED_TOOLS.get(tool_name)


def get_all_tools() -> Dict[str, BaseTool]:
    """Get a dictionary of all loaded tool instances."""
    if not _INITIALIZED:
        initialize_system()
    return _LOADED_TOOLS.copy()  # Return a copy
