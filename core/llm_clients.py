"""LLM client interfaces and factory function."""

import logging
from typing import Dict

from providers.llm import BedrockProvider, CerebrasProvider, LLMProvider, OpenAIProvider

logger = logging.getLogger(__name__)

# Cache of initialized providers to avoid recreating them
_PROVIDER_INSTANCES: Dict[str, LLMProvider] = {}


def get_llm_client(provider_key: str) -> LLMProvider:
    """Get or create an LLM client for the specified provider.

    Args:
        provider_key: String key for the provider (e.g., 'openai', 'aws_bedrock')

    Returns:
        LLMProvider instance

    Raises:
        ValueError: If provider_key is not recognized or configuration is invalid
    """
    if provider_key in _PROVIDER_INSTANCES:
        return _PROVIDER_INSTANCES[provider_key]

    # Import here to avoid circular imports
    from core.initialization import _load_yaml_config

    try:
        # Load provider configurations from YAML
        provider_configs = _load_yaml_config("config/providers.yaml")

        if provider_key not in provider_configs:
            raise ValueError(
                f"Provider '{provider_key}' not found in provider configurations"
            )

        config = provider_configs[provider_key]

        # Create appropriate provider instance based on provider_key
        if provider_key == "openai":
            provider = OpenAIProvider(config, provider_key)
        elif provider_key == "azure_openai":
            provider = OpenAIProvider(
                config, provider_key
            )  # Same class, different config
        elif provider_key == "aws_bedrock":
            provider = BedrockProvider(config)
        elif provider_key == "cerebras":
            provider = CerebrasProvider(config)
        else:
            raise ValueError(f"Unsupported provider: {provider_key}")

        # Cache the instance
        _PROVIDER_INSTANCES[provider_key] = provider
        logger.info(f"Initialized LLM provider: {provider_key}")
        return provider

    except Exception as e:
        logger.exception(f"Failed to initialize LLM provider '{provider_key}': {e}")
        raise ValueError(
            f"Failed to initialize LLM provider '{provider_key}': {e}"
        ) from e
