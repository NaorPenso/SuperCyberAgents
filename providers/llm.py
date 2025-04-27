"""LLM Provider Abstraction."""

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict

import requests

# Optional imports - handle gracefully if extras not installed
try:
    import boto3
    from botocore.exceptions import NoCredentialsError
except ImportError:
    boto3 = None
    NoCredentialsError = None

try:
    import openai
except ImportError:
    openai = None


logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize provider with its specific configuration section."""
        self.config = config

    @abstractmethod
    def generate(self, prompt: str, model: str, **kwargs: Any) -> str:
        """Generate text from a prompt using the specified model and parameters."""
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    """LLM Provider implementation for OpenAI and Azure OpenAI."""

    def __init__(self, config: Dict[str, Any], provider_key: str):
        super().__init__(config)
        if not openai:
            raise ImportError(
                "OpenAI library not installed. Please install with `poetry install --extras openai` or `pip install openai`."
            )

        self.provider_key = provider_key  # 'openai' or 'azure_openai'
        self.client = None

        # Configure based on provider type
        if self.provider_key == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable not set.")
            self.client = openai.OpenAI(
                api_key=api_key, base_url=config.get("api_base")
            )
            logger.info("Initialized OpenAI provider.")

        elif self.provider_key == "azure_openai":
            api_key = os.getenv("AZURE_OPENAI_API_KEY")
            endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            # deployment_name is per-agent model in this design, passed in generate
            if not api_key or not endpoint:
                raise ValueError(
                    "AZURE_OPENAI_API_KEY or AZURE_OPENAI_ENDPOINT env var not set."
                )
            self.client = openai.AzureOpenAI(
                api_key=api_key,
                azure_endpoint=endpoint,
                api_version=config.get("api_version", "2023-05-15"),
            )
            logger.info("Initialized Azure OpenAI provider.")
        else:
            raise ValueError(f"Unsupported OpenAI provider key: {self.provider_key}")

    def generate(self, prompt: str, model: str, **kwargs: Any) -> str:
        """Generate text using OpenAI or Azure OpenAI API."""
        if not self.client:
            raise RuntimeError("OpenAI client not initialized.")

        logger.debug(f"Generating text with {self.provider_key} model: {model}")
        try:
            # Use ChatCompletion endpoint
            response = self.client.chat.completions.create(
                model=model,  # For Azure, this is the deployment name
                messages=[{"role": "user", "content": prompt}],
                **kwargs,  # Pass parameters like temperature, max_tokens
            )
            # Access the first choice's message content
            if response.choices and response.choices[0].message:
                return response.choices[0].message.content or ""
            else:
                logger.warning("LLM response did not contain expected content.")
                return ""
        except Exception as e:
            logger.exception(f"{self.provider_key} API call failed: {e}")
            raise  # Re-raise the exception to be handled by the caller


class BedrockProvider(LLMProvider):
    """LLM Provider implementation for AWS Bedrock."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        if not boto3 or not NoCredentialsError:
            raise ImportError(
                "AWS SDK (boto3) not installed. Please install with `poetry install --extras aws` or `pip install boto3`."
            )

        region = os.getenv("AWS_REGION", config.get("region"))
        profile = os.getenv("AWS_PROFILE", config.get("profile"))

        # Explicitly check for region before attempting connection
        if not region:
            # Raise ValueError to be caught by the initialization loop
            raise ValueError(
                "AWS Bedrock provider requires a region. "
                "Set AWS_REGION env var or 'region' in config/providers.yaml."
            )

        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            self.client = session.client("bedrock-runtime")
            logger.info(
                f"Initialized AWS Bedrock provider in region: {session.region_name}"
            )
        except NoCredentialsError:
            logger.error(
                "AWS credentials not found. Configure credentials via environment variables, "
                "shared credential file, or IAM role."
            )
            raise
        except Exception as e:
            logger.exception(f"Failed to initialize AWS Bedrock client: {e}")
            raise

    def generate(self, prompt: str, model: str, **kwargs: Any) -> str:
        """Generate text using AWS Bedrock invoke_model API."""
        if not self.client:
            raise RuntimeError("AWS Bedrock client not initialized.")

        # Bedrock requires different payload structures per model provider
        # Example for Anthropic Claude models:
        if model.startswith("anthropic.claude"):
            body = json.dumps(
                {
                    "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                    "max_tokens_to_sample": kwargs.get("max_tokens", 500),
                    "temperature": kwargs.get("temperature", 0.7),
                    # Add other Claude-specific params if needed
                }
            )
            accept = "application/json"
            content_type = "application/json"
        else:
            # Add logic for other model types (e.g., AI21, Cohere, Meta Llama) as needed
            # This requires checking the model ID and formatting the body accordingly.
            logger.error(f"Bedrock model type for '{model}' not implemented yet.")
            raise NotImplementedError(
                f"Bedrock support for model '{model}' is not implemented."
            )

        logger.debug(f"Generating text with AWS Bedrock model: {model}")
        try:
            response = self.client.invoke_model(
                body=body,
                modelId=model,
                accept=accept,
                contentType=content_type,
            )
            response_body = json.loads(response.get("body").read())

            # Extract completion based on model provider response structure
            if model.startswith("anthropic.claude"):
                return response_body.get("completion", "")
            else:
                # Adapt for other models
                return ""

        except Exception as e:
            logger.exception(f"AWS Bedrock API call failed: {e}")
            raise


class CerebrasProvider(LLMProvider):
    """Hypothetical LLM Provider implementation for Cerebras."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Use CEREBRAS_API_BASE for the base URL
        self.api_base = os.getenv("CEREBRAS_API_BASE")
        self.api_key = os.getenv("CEREBRAS_API_KEY")

        if not self.api_base:
            raise ValueError("CEREBRAS_API_BASE environment variable not set.")
        if not self.api_key:
            raise ValueError("CEREBRAS_API_KEY environment variable not set.")

        logger.info(
            f"Initialized Cerebras provider targeting base URL: {self.api_base}"
        )

    def generate(self, prompt: str, model: str, **kwargs: Any) -> str:
        """Generate text using a hypothetical Cerebras REST API."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        # Structure payload based on common API patterns - adjust if needed
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            **kwargs,  # Pass parameters like temperature, max_tokens
        }
        # Assume endpoint is the base, add specific path like /generate
        # Assuming a standard chat/completions endpoint structure
        generate_url = f"{self.api_base.rstrip('/')}/chat/completions"

        logger.debug(
            f"Generating text with Cerebras model '{model}' via {generate_url}"
        )
        try:
            response = requests.post(
                generate_url,
                json=payload,
                headers=headers,
                timeout=60,  # Example timeout
            )
            response.raise_for_status()
            data = response.json()
            # Adapt based on actual Cerebras API response structure
            # Example: Assuming OpenAI-like response structure
            if data.get("choices") and data["choices"][0].get("message"):
                return data["choices"][0]["message"].get("content", "")
            return data.get("generated_text", "")  # Fallback or adjust as needed
        except requests.exceptions.RequestException as e:
            logger.exception(f"Cerebras API call failed: {e}")
            raise
        except Exception as e:
            logger.exception(f"Error processing Cerebras response: {e}")
            raise
