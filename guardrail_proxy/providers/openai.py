"""Adapter for any OpenAI-compatible backend.

Ollama, vLLM, LM Studio, llama.cpp server, OpenRouter, Mistral, Groq,
DeepSeek, Gemini's compatibility endpoint and OpenAI itself all expose
``POST {base}/chat/completions`` with the same schema, so this one adapter
covers local and hosted models: only ``GUARD_BACKEND_URL`` changes.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..config import Settings
from .base import BackendError, Result

DEFAULT_URL = "http://localhost:11434/v1"  # a local Ollama


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        headers = {"User-Agent": "llm-guardrail-proxy"}
        if settings.backend_api_key:
            headers.update(self._auth_headers(settings.backend_api_key.get_secret_value()))
        self._client = httpx.AsyncClient(
            base_url=self._base_url(settings).rstrip("/") + "/",
            headers=headers,
            timeout=settings.backend_timeout_s,
            transport=transport,
        )

    def _base_url(self, settings: Settings) -> str:
        return settings.backend_url or DEFAULT_URL

    def _auth_headers(self, key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {key}"}

    def _chat_path(self, payload: dict[str, Any]) -> str:
        return "chat/completions"

    async def chat_completions(self, payload: dict[str, Any]) -> Result:
        return await self._call("POST", self._chat_path(payload), json=payload)

    async def models(self) -> Result:
        return await self._call("GET", "models")

    async def _call(self, method: str, path: str, **kwargs: Any) -> Result:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise BackendError(f"{type(exc).__name__}: backend unreachable") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise BackendError(f"backend returned non-JSON (HTTP {resp.status_code})") from exc
        if not isinstance(body, dict):
            raise BackendError("backend returned a non-object JSON body")
        return resp.status_code, body

    async def aclose(self) -> None:
        await self._client.aclose()
