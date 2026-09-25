"""Runtime configuration, read from environment variables (prefix ``GUARD_``)."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class InjectionAction(StrEnum):
    BLOCK = "block"  # reject the request with HTTP 400
    FLAG = "flag"  # forward it, but record the finding in the audit log


class OutputAction(StrEnum):
    BLOCK = "block"  # replace the whole answer with a refusal (finish_reason=content_filter)
    REDACT = "redact"  # mask leaked secrets, keep the rest of the answer
    FLAG = "flag"  # forward untouched, audit only


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARD_", env_file=".env", extra="ignore")

    # Any OpenAI-compatible backend: OpenAI, Azure/OpenRouter/vLLM gateways,
    # or Ollama, which serves the same schema under http://ollama:11434/v1.
    backend_url: str = "http://localhost:11434/v1"
    backend_api_key: SecretStr | None = None
    backend_timeout_s: float = 60.0

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
