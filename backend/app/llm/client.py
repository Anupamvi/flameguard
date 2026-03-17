"""Claude API wrapper using the anthropic SDK."""

from __future__ import annotations

import anthropic

from app.config import settings


class ClaudeClient:
    """Thin wrapper around the Anthropic Python SDK."""

    def __init__(self) -> None:
        if not settings.anthropic_api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. "
                "Please add it to your .env file or set it as an environment variable."
            )
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
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
