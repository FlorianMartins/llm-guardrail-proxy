"""OpenAI-compatible routes: the proxy's data path."""

from __future__ import annotations

import hmac
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from .audit import audit, digest
from .config import Settings
from .pipeline import inspect_input, inspect_output, system_prompts
from .providers import BackendError, Provider
from .schemas import ChatCompletionRequest, openai_error

router = APIRouter()


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _backend(request: Request) -> Provider:
    return request.app.state.backend


def require_client_key(request: Request, settings: Settings = Depends(_settings)) -> None:
    if not settings.proxy_api_keys:
        return
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    # compare_digest against every key: no early exit, no timing oracle.
    ok = False
    for key in settings.proxy_api_keys:
        ok |= hmac.compare_digest(token.encode(), key.get_secret_value().encode())
    if not ok:
        raise HTTPException(401, detail="invalid or missing proxy API key")


def _err(status: int, message: str, type_: str, code: str | None = None) -> JSONResponse:
    return JSONResponse(openai_error(message, type_, code), status_code=status)


@router.get("/v1/models", dependencies=[Depends(require_client_key)])
async def list_models(backend: Provider = Depends(_backend)) -> JSONResponse:
    try:
        status, body = await backend.models()
    except BackendError as exc:
        return _err(502, str(exc), "backend_error")
    return JSONResponse(body, status_code=status)


@router.post("/v1/chat/completions", dependencies=[Depends(require_client_key)])
async def chat_completions(
    request: Request,
    settings: Settings = Depends(_settings),
    backend: Provider = Depends(_backend),
):
    started = time.perf_counter()
    rid = request.state.request_id
    event: dict[str, Any] = {
        "request_id": rid,
        "provider": backend.name,
        "client_ip": request.client.host if request.client else None,
    }

    def _done(decision: str, **extra: Any) -> None:
        audit(
            "chat.completions",
            **event,
            decision=decision,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            **extra,
        )

    # 1. Parse, with a hard size ceiling (we scan every byte, so bound the work).
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        _done("rejected", reason="body_too_large", body_bytes=len(raw))
        return _err(413, "request body too large", "invalid_request_error", "body_too_large")
    try:
        req = ChatCompletionRequest.model_validate_json(raw)
    except ValidationError as exc:
        _done("rejected", reason="invalid_schema")
        return _err(400, f"invalid request: {exc.errors()[0]['msg']}", "invalid_request_error")

    payload = req.model_dump(exclude_none=True)
    event.update(
        model=req.model,
        stream=req.stream,
        message_count=len(req.messages),
        prompt_digest=digest(payload["messages"]),
    )

    # 2. Input guardrails.
    verdict = inspect_input(payload["messages"], settings)
    input_findings = [f.as_dict() for f in verdict.findings]
    event.update(injection_score=round(verdict.injection_score, 2))
    if verdict.blocked:
        _done("blocked_input", findings=input_findings)
        return _err(
            400,
            "Request blocked by the security proxy: possible prompt injection.",
            "guardrail_violation",
            "prompt_injection",
        )

    # 3. Forward. Streaming requests are fetched whole and re-emitted as SSE:
    #    output validation needs the complete answer, and a secret split across
    #    two chunks would slip past a chunk-by-chunk filter.
    upstream = {**payload, "messages": verdict.messages, "stream": False}
    upstream.pop("stream_options", None)
    t_backend = time.perf_counter()
    try:
        status, body = await backend.chat_completions(upstream)
    except BackendError as exc:
        _done("backend_error", findings=input_findings, error=str(exc))
        return _err(502, "LLM backend unavailable", "backend_error")
    backend_ms = round((time.perf_counter() - t_backend) * 1000, 2)

    if status >= 400:
        _done(
            "backend_error", findings=input_findings, backend_status=status, backend_ms=backend_ms
        )
        return JSONResponse(body, status_code=status)

    # 4. Output guardrails.
    out = inspect_output(body, system_prompts(payload["messages"]), settings)
    findings = input_findings + [f.as_dict() for f in out.findings]
    _done(
        "filtered_output" if out.filtered else ("flagged" if findings else "allowed"),
        findings=findings,
        backend_ms=backend_ms,
        usage=body.get("usage"),
    )

    headers = {"X-Guardrail-Findings": str(len(findings))}
    if req.stream:
        return StreamingResponse(_as_sse(out.body), media_type="text/event-stream", headers=headers)
    return JSONResponse(out.body, headers=headers)


async def _as_sse(body: dict[str, Any]) -> AsyncIterator[bytes]:
    """Re-emit a complete chat.completion as OpenAI ``chat.completion.chunk`` events."""
    base = {
        "id": body.get("id"),
        "object": "chat.completion.chunk",
        "created": body.get("created", int(time.time())),
        "model": body.get("model"),
    }

    def _evt(obj: dict[str, Any]) -> bytes:
        return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode()

    for choice in body.get("choices") or []:
        i = choice.get("index", 0)
        msg = choice.get("message") or {}
        delta = {"role": msg.get("role", "assistant"), "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            delta["tool_calls"] = [{**tc, "index": n} for n, tc in enumerate(msg["tool_calls"])]
        yield _evt({**base, "choices": [{"index": i, "delta": delta, "finish_reason": None}]})
        yield _evt(
            {
                **base,
                "choices": [
                    {"index": i, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}
                ],
            }
        )
    yield b"data: [DONE]\n\n"
