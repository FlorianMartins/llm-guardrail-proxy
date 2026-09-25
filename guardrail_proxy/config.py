"""Runtime configuration, read from environment variables (prefix ``GUARD_``)."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class BackendProvider(StrEnum):
    OPENAI = "openai"  # any OpenAI-compatible API: OpenAI, Ollama, vLLM, OpenRouter, Mistral...
    AZURE = "azure"  # Azure OpenAI (deployment URLs, api-key header)
    ANTHROPIC = "anthropic"  # Anthropic Messages API (Claude), translated both ways


class InjectionAction(StrEnum):
    BLOCK = "block"  # reject the request with HTTP 400
    FLAG = "flag"  # forward it, but record the finding in the audit log


class OutputAction(StrEnum):
    BLOCK = "block"  # replace the whole answer with a refusal (finish_reason=content_filter)
    REDACT = "redact"  # mask leaked secrets, keep the rest of the answer
    FLAG = "flag"  # forward untouched, audit only


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARD_", env_file=".env", extra="ignore")

    backend_provider: BackendProvider = BackendProvider.OPENAI
    # openai: base URL, defaults to a local Ollama (http://localhost:11434/v1).
    # azure: the resource endpoint, https://<resource>.openai.azure.com (required).
    # anthropic: optional override of https://api.anthropic.com.
    backend_url: str | None = None
    backend_api_key: SecretStr | None = None
    backend_timeout_s: float = 60.0

    azure_api_version: str = "2024-10-21"
    # Anthropic requires max_tokens; used when the client does not send one.
    anthropic_max_tokens: int = Field(default=16000, gt=0)

    # Optional client authentication for the proxy itself. Empty = open (dev only).
    proxy_api_keys: list[SecretStr] = Field(default_factory=list)

    injection_action: InjectionAction = InjectionAction.BLOCK
    injection_threshold: float = Field(default=0.8, ge=0.0)
    mask_pii: bool = True
    output_action: OutputAction = OutputAction.REDACT

    # Hard ceiling on the request body we are willing to parse and scan.
    max_body_bytes: int = 1_000_000

    host: str = "0.0.0.0"  # noqa: S104 - container default; bind narrower on a bare host
    port: int = 8000

    log_level: str = "INFO"
    log_file: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
