"""LLM API wrapper — supports OpenAI direct API and Azure AI Foundry (OpenAI-compatible)."""

from __future__ import annotations

from typing import Any

from openai import AzureOpenAI, OpenAI

from app.config import settings


def _build_client() -> OpenAI | AzureOpenAI:
    """Create the appropriate OpenAI client based on LLM_PROVIDER setting.

    - "openai": Direct OpenAI API (requires OPENAI_API_KEY)
    - "azure": Azure AI Foundry (requires AZURE_ENDPOINT and AZURE_API_KEY)
    """
    if settings.llm_provider == "azure":
        if not settings.azure_endpoint:
            raise RuntimeError(
                "LLM_PROVIDER is 'azure' but AZURE_ENDPOINT is not set. "
                "Set it to your Azure AI Foundry endpoint, e.g. "
                "https://<resource>.services.ai.azure.com"
            )
        if not settings.azure_api_key:
            raise RuntimeError(
                "LLM_PROVIDER is 'azure' but AZURE_API_KEY is not set."
            )
        return AzureOpenAI(
            azure_endpoint=settings.azure_endpoint,
            api_key=settings.azure_api_key,
            api_version=settings.azure_api_version,
        )

    # Default: direct OpenAI API
    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. "
            "Please add it to your .env file or set it as an environment variable. "
            "Alternatively, set LLM_PROVIDER=azure to use Azure AI Foundry."
        )
    return OpenAI(api_key=settings.openai_api_key)


class LLMClient:
    """Thin wrapper around the OpenAI Python SDK.

    Automatically uses the correct backend (OpenAI or Azure AI Foundry)
    based on the LLM_PROVIDER environment variable.
    """

    def __init__(self) -> None:
        self.client = _build_client()
        self.model = settings.llm_model

    async def analyze(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        """Call the LLM and return the text response."""
        request_args: dict[str, Any] = {
            "model": self.model,
            "max_completion_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if response_format is not None:
            request_args["response_format"] = response_format

        response = self.client.chat.completions.create(
            **request_args,
        )
        content = response.choices[0].message.content
        if content is None:
            raise ValueError("LLM returned empty content (None)")
        return content

    def stream(
        self,
        system: str,
        user: str | None = None,
        messages: list[dict] | None = None,
        max_tokens: int = 4096,
    ):
        """Return a streaming response for SSE chat."""
        msgs = [{"role": "system", "content": system}]
        if messages:
            msgs.extend(messages)
        else:
            if user is None:
                raise ValueError("user is required when messages are not provided")
            msgs.append({"role": "user", "content": user})
        return self.client.chat.completions.create(
            model=self.model,
            max_completion_tokens=max_tokens,
            messages=msgs,
            stream=True,
        )


# Keep backward-compatible alias
ClaudeClient = LLMClient
