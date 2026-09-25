"""Adapter for Anthropic's Messages API (Claude), through the official SDK.

Clients keep speaking OpenAI; this module translates at the edge:

    OpenAI chat.completions                 Anthropic messages
    ───────────────────────                 ──────────────────
    role "system" / "developer"        ──►  top-level ``system``
    content parts text / image_url     ──►  text / image blocks
    assistant.tool_calls               ──►  tool_use blocks
    role "tool"                        ──►  tool_result blocks in a user turn
    tools / tool_choice                ──►  tools / tool_choice
    max_(completion_)tokens            ──►  max_tokens (required by Anthropic)
    stop                               ──►  stop_sequences
    reasoning_effort                   ──►  output_config.effort
    response_format json_schema        ──►  output_config.format
    ◄── stop_reason → finish_reason, usage → prompt/completion tokens

Sampling parameters (``temperature``, ``top_p``) are *not* forwarded: current
Claude models reject them, and ``reasoning_effort`` is the supported control.
Parameters with no Anthropic equivalent (``n``, ``logprobs``, penalties...)
are dropped.
"""

from __future__ import annotations

import json
import time
from typing import Any

import anthropic

from ..config import Settings
from ..schemas import openai_error
from .base import BackendError, Result

FINISH_REASON = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "pause_turn": "stop",
    "max_tokens": "length",
    "model_context_window_exceeded": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
}

EFFORTS = {"low", "medium", "high", "xhigh", "max"}


# --- request: OpenAI -> Anthropic ---------------------------------------------


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
        )
    return ""


def _image_block(part: dict[str, Any]) -> dict[str, Any]:
    image = part.get("image_url") or {}
    url = image.get("url", "") if isinstance(image, dict) else str(image)
    if url.startswith("data:") and ";base64," in url:
        media_type, data = url[5:].split(";base64,", 1)
        return {
            "type": "image",
            "source": {"type": "base64", "media_type": media_type, "data": data},
        }
    return {"type": "image", "source": {"type": "url", "url": url}}


def _blocks(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    blocks: list[dict[str, Any]] = []
    for part in content or []:
        if not isinstance(part, dict):
            continue
        if part.get("type") == "text" and part.get("text"):
            blocks.append({"type": "text", "text": part["text"]})
        elif part.get("type") == "image_url":
            blocks.append(_image_block(part))
    return blocks


def _tool_use_blocks(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = []
    for call in tool_calls:
        fn = call.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments")}
        blocks.append(
            {
                "type": "tool_use",
                "id": call.get("id"),
                "name": fn.get("name"),
                "input": args if isinstance(args, dict) else {"value": args},
            }
        )
    return blocks


def _tool_choice(choice: Any, parallel: bool | None) -> dict[str, Any] | None:
    if choice is None and parallel is None:
        return None
    if isinstance(choice, dict):
        name = (choice.get("function") or {}).get("name")
        out: dict[str, Any] = {"type": "tool", "name": name}
    else:
        out = {"type": {"none": "none", "required": "any"}.get(choice, "auto")}
    if parallel is False and out["type"] != "none":
        out["disable_parallel_tool_use"] = True
    return out


def to_anthropic(payload: dict[str, Any], default_max_tokens: int) -> dict[str, Any]:
    system: list[str] = []
    messages: list[dict[str, Any]] = []

    def _append(role: str, blocks: list[dict[str, Any]]) -> None:
        if not blocks:
            return
        # Consecutive same-role turns are merged: this is also how several
        # parallel tool results end up in the single user turn Claude expects.
        if messages and messages[-1]["role"] == role:
            messages[-1]["content"].extend(blocks)
        else:
            messages.append({"role": role, "content": blocks})

    for msg in payload.get("messages", []):
        role = msg.get("role")
        if role in {"system", "developer"}:
            if text := _text_of(msg.get("content")):
                system.append(text)
        elif role == "user":
            _append("user", _blocks(msg.get("content")))
        elif role == "assistant":
            _append(
                "assistant",
                _blocks(msg.get("content")) + _tool_use_blocks(msg.get("tool_calls") or []),
            )
        elif role in {"tool", "function"}:
            _append(
                "user",
                [
                    {
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id"),
                        "content": _text_of(msg.get("content")),
                    }
                ],
            )

    params: dict[str, Any] = {
        "model": payload["model"],
        "messages": messages,
        "max_tokens": payload.get("max_completion_tokens")
        or payload.get("max_tokens")
        or default_max_tokens,
    }
    if system:
        params["system"] = "\n\n".join(system)

    stop = payload.get("stop")
    if stop:
        params["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)

    if tools := payload.get("tools"):
        converted = []
        for tool in tools:
            fn = tool.get("function") or {}
            spec = {
                "name": fn.get("name"),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            }
            if fn.get("description"):
                spec["description"] = fn["description"]
            if fn.get("strict"):
                spec["strict"] = True
            converted.append(spec)
        params["tools"] = converted
        if choice := _tool_choice(payload.get("tool_choice"), payload.get("parallel_tool_calls")):
            params["tool_choice"] = choice

    output_config: dict[str, Any] = {}
    if payload.get("reasoning_effort") in EFFORTS:
        output_config["effort"] = payload["reasoning_effort"]
    fmt = payload.get("response_format") or {}
    if fmt.get("type") == "json_schema" and (fmt.get("json_schema") or {}).get("schema"):
        output_config["format"] = {"type": "json_schema", "schema": fmt["json_schema"]["schema"]}
    if output_config:
        params["output_config"] = output_config

    if isinstance(payload.get("user"), str):
        params["metadata"] = {"user_id": payload["user"]}
    return params


# --- response: Anthropic -> OpenAI --------------------------------------------


def from_anthropic(msg: dict[str, Any]) -> dict[str, Any]:
    text: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in msg.get("content") or []:
        if block.get("type") == "text":
            text.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(
                {
                    "id": block.get("id"),
                    "type": "function",
                    "function": {
                        "name": block.get("name"),
                        "arguments": json.dumps(block.get("input") or {}),
                    },
                }
            )
        # thinking blocks are internal reasoning: not part of the OpenAI answer.

    message: dict[str, Any] = {"role": "assistant", "content": "".join(text) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls

    usage = msg.get("usage") or {}
    prompt = sum(
        usage.get(k) or 0
        for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    )
    completion = usage.get("output_tokens") or 0
    return {
        "id": msg.get("id"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": msg.get("model"),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": FINISH_REASON.get(msg.get("stop_reason") or "", "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    }


def _error_body(exc: anthropic.APIStatusError) -> dict[str, Any]:
    err = exc.body.get("error", {}) if isinstance(exc.body, dict) else {}
    return openai_error(err.get("message") or exc.message, err.get("type") or "api_error")


# --- provider ---------------------------------------------------------------------


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        settings: Settings,
        http_client: anthropic.DefaultAsyncHttpxClient | None = None,
    ):
        kwargs: dict[str, Any] = {"timeout": settings.backend_timeout_s}
        if settings.backend_api_key:
            kwargs["api_key"] = settings.backend_api_key.get_secret_value()
        if settings.backend_url:  # the SDK appends /v1/messages itself
            kwargs["base_url"] = settings.backend_url.rstrip("/").removesuffix("/v1")
        if http_client is not None:
            kwargs["http_client"] = http_client
        self._client = anthropic.AsyncAnthropic(**kwargs)
        self._max_tokens = settings.anthropic_max_tokens

    async def chat_completions(self, payload: dict[str, Any]) -> Result:
        try:
            msg = await self._client.messages.create(**to_anthropic(payload, self._max_tokens))
        except anthropic.APIStatusError as exc:
            return exc.status_code, _error_body(exc)
        except anthropic.APIConnectionError as exc:
            raise BackendError(f"{type(exc).__name__}: backend unreachable") from exc
        return 200, from_anthropic(msg.model_dump(mode="json"))

    async def models(self) -> Result:
        try:
            page = await self._client.models.list(limit=100)
        except anthropic.APIStatusError as exc:
            return exc.status_code, _error_body(exc)
        except anthropic.APIConnectionError as exc:
            raise BackendError(f"{type(exc).__name__}: backend unreachable") from exc
        data = [
            {
                "id": m.id,
                "object": "model",
                "created": int(m.created_at.timestamp()),
                "owned_by": "anthropic",
            }
            for m in page.data
        ]
        return 200, {"object": "list", "data": data}

    async def aclose(self) -> None:
        await self._client.close()
