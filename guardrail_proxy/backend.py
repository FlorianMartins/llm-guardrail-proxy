"""Thin async client for any OpenAI-compatible backend.

Ollama, vLLM, LM Studio, llama.cpp server, OpenRouter and OpenAI itself all
expose ``POST {base}/chat/completions`` with the same schema, so a single
client covers local and hosted models; only ``GUARD_BACKEND_URL`` changes.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class BackendError(Exception):
    """The backend could not be reached or answered garbage."""


class Backend:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        headers = {"User-Agent": "llm-guardrail-proxy"}
        if settings.backend_api_key:
            headers["Authorization"] = f"Bearer {settings.backend_api_key.get_secret_value()}"
        self._client = httpx.AsyncClient(
            base_url=settings.backend_url.rstrip("/") + "/",
            headers=headers,
            timeout=settings.backend_timeout_s,
            transport=transport,
        )

    async def chat_completions(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return await self._call("POST", "chat/completions", json=payload)

    async def models(self) -> tuple[int, dict[str, Any]]:
        return await self._call("GET", "models")

    async def _call(self, method: str, path: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
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
