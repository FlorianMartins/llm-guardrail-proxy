"""Request schema. Deliberately permissive (``extra="allow"``): the proxy
validates what it must inspect and forwards every other OpenAI parameter
(temperature, tools, response_format...) untouched."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[dict[str, Any]] | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False


def openai_error(message: str, type_: str, code: str | None = None) -> dict[str, Any]:
    return {"error": {"message": message, "type": type_, "code": code, "param": None}}
