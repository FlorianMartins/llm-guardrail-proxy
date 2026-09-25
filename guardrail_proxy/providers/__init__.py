"""Backend adapters. Pick one with ``GUARD_BACKEND_PROVIDER``."""

from __future__ import annotations

from ..config import BackendProvider, Settings
from .base import BackendError, Provider, Result


def build_provider(settings: Settings) -> Provider:
    if settings.backend_provider is BackendProvider.ANTHROPIC:
        from .anthropic import AnthropicProvider

        return AnthropicProvider(settings)
    if settings.backend_provider is BackendProvider.AZURE:
        from .azure import AzureOpenAIProvider

        return AzureOpenAIProvider(settings)
    from .openai import OpenAICompatibleProvider

    return OpenAICompatibleProvider(settings)


__all__ = ["BackendError", "Provider", "Result", "build_provider"]
