"""Claude API wrapper — supports both direct Anthropic API and Azure AI Foundry."""

from __future__ import annotations

import anthropic

from app.config import settings


def _build_client() -> anthropic.Anthropic:
    """Create the appropriate Anthropic client based on LLM_PROVIDER setting.

    - "anthropic": Direct Anthropic API (requires ANTHROPIC_API_KEY)
    - "azure": Azure AI Foundry / Azure AI Model Catalog
              (requires AZURE_ENDPOINT, and optionally AZURE_API_KEY)
    """
    if settings.llm_provider == "azure":
        if not settings.azure_endpoint:
            raise RuntimeError(
                "LLM_PROVIDER is 'azure' but AZURE_ENDPOINT is not set. "
                "Set it to your Azure AI Foundry endpoint, e.g. "
                "https://<resource>.services.ai.azure.com"
            )

        # Azure AI Foundry with API key auth
        if settings.azure_api_key:
            return anthropic.AnthropicAzure(
                azure_endpoint=settings.azure_endpoint,
                azure_api_key=settings.azure_api_key,
                azure_api_version=settings.azure_api_version,
            )

        # Azure AI Foundry with Entra ID / DefaultAzureCredential (keyless)
        # Requires: pip install azure-identity
        try:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        except ImportError:
            raise RuntimeError(
                "AZURE_API_KEY is not set and azure-identity is not installed. "
                "Either set AZURE_API_KEY or install azure-identity: "
                "pip install azure-identity"
            )

        credential = DefaultAzureCredential()
        token_provider = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default"
        )
        return anthropic.AnthropicAzure(
            azure_endpoint=settings.azure_endpoint,
            azure_ad_token_provider=token_provider,
            azure_api_version=settings.azure_api_version,
        )

    # Default: direct Anthropic API
    if not settings.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. "
            "Please add it to your .env file or set it as an environment variable. "
            "Alternatively, set LLM_PROVIDER=azure to use Azure AI Foundry."
        )
    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


class ClaudeClient:
    """Thin wrapper around the Anthropic Python SDK.

    Automatically uses the correct backend (Anthropic or Azure AI Foundry)
    based on the LLM_PROVIDER environment variable.
    """

    def __init__(self) -> None:
        self.client = _build_client()
        self.model = settings.claude_model

    async def analyze(self, system: str, user: str, max_tokens: int = 4096) -> str:
        """Call Claude and return the text response.

        Uses the sync client in an async context -- acceptable for background
        pipeline work where we are not blocking the request thread.
        """
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    def stream(
        self,
        system: str,
        user: str,
        messages: list[dict] | None = None,
        max_tokens: int = 4096,
    ):
        """Return a streaming response context-manager for SSE chat."""
        msgs = messages or [{"role": "user", "content": user}]
        return self.client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=msgs,
        )
