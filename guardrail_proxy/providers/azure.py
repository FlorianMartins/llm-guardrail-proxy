"""Adapter for Azure OpenAI.

Same JSON schema as OpenAI, different transport details:

* the URL names a *deployment*, not a model:
  ``{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...``
  The proxy uses the request's ``model`` field as the deployment name, so
  clients keep sending ``model="my-gpt-deployment"`` as usual;
* the key travels in an ``api-key`` header instead of ``Authorization``.

Azure's own content filter answers HTTP 400 ``content_filter``; it is passed
through untouched, so the client sees which layer refused.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from ..config import Settings
from ..schemas import openai_error
from .base import Result
from .openai import OpenAICompatibleProvider

# Azure deployment names: letters, digits, "-", "_" and ".". Anything else is
# refused rather than escaped, so a crafted "model" can never reshape the URL.
_DEPLOYMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AzureOpenAIProvider(OpenAICompatibleProvider):
    name = "azure"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._api_version = settings.azure_api_version
        super().__init__(settings, transport)

    def _base_url(self, settings: Settings) -> str:
        if not settings.backend_url:
            raise ValueError(
                "GUARD_BACKEND_URL must be your Azure endpoint, "
                "e.g. https://my-resource.openai.azure.com"
            )
        return settings.backend_url

    def _auth_headers(self, key: str) -> dict[str, str]:
        return {"api-key": key}

    def _chat_path(self, payload: dict[str, Any]) -> str:
        deployment = quote(str(payload.get("model", "")), safe="")
        return f"openai/deployments/{deployment}/chat/completions?api-version={self._api_version}"

    async def chat_completions(self, payload: dict[str, Any]) -> Result:
        if not _DEPLOYMENT.match(str(payload.get("model", ""))):
            return 400, openai_error(
                "`model` must be an Azure deployment name", "invalid_request_error", "bad_model"
            )
        # The deployment already pins the model; Azure ignores or rejects the field.
        body = {k: v for k, v in payload.items() if k != "model"}
        return await self._call("POST", self._chat_path(payload), json=body)

    async def models(self) -> Result:
        # Deployments are listed through the Azure management plane, not this API.
        return 501, openai_error(
            "Model listing is not available through Azure OpenAI; "
            "use your deployment name as the `model` field.",
            "not_supported",
        )
