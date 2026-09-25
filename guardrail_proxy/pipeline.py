"""Guardrail pipeline: turns guard findings into a policy decision.

Guards only *observe*; this module *decides*, based on Settings. Keeping the
two apart means a new guard (say, an ML classifier) plugs in without
touching policy, and a policy change never requires touching detection code.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from .config import InjectionAction, OutputAction, Settings
from .guards import Finding, Stage, injection, output, pii

# Roles whose content is attacker-reachable. System prompts are written by the
# application developer and are trusted; tool results are NOT (indirect
# injection through a web page or a document the agent fetched).
INJECTION_ROLES = {"user", "tool", "function"}
PII_ROLES = {"user", "tool", "function", "assistant"}

REFUSAL = "This response was withheld by the security proxy because it violated output policy."


@dataclass
class InputVerdict:
    messages: list[dict[str, Any]]
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False
    injection_score: float = 0.0


@dataclass
class OutputVerdict:
    body: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    filtered: bool = False


def _map_text(content: Any, fn) -> Any:
    """Apply ``fn`` to the text of a message, whatever its shape
    (plain string or OpenAI multimodal list of parts)."""
    if isinstance(content, str):
        return fn(content)
    if isinstance(content, list):
        out = []
        for part in content:
            if (
                isinstance(part, dict)
                and part.get("type") == "text"
                and isinstance(part.get("text"), str)
            ):
                part = {**part, "text": fn(part["text"])}
            out.append(part)
        return out
    return content


def inspect_input(messages: list[dict[str, Any]], settings: Settings) -> InputVerdict:
    messages = copy.deepcopy(messages)  # never mutate the caller's payload
    verdict = InputVerdict(messages=messages)

    for idx, msg in enumerate(messages):
        role = msg.get("role")

        if role in INJECTION_ROLES:
            msg_score = 0.0

            def _scan(text: str, idx: int = idx) -> str:
                nonlocal msg_score
                score, found = injection.scan(text, idx)
                msg_score += score
                verdict.findings.extend(found)
                return text

            _map_text(msg.get("content"), _scan)
            verdict.injection_score = max(verdict.injection_score, msg_score)

        if settings.mask_pii and role in PII_ROLES:

            def _mask(text: str, idx: int = idx) -> str:
                masked, found = pii.redact(text, Stage.INPUT, idx)
                verdict.findings.extend(found)
                return masked

            msg["content"] = _map_text(msg.get("content"), _mask)

    verdict.blocked = (
        settings.injection_action is InjectionAction.BLOCK
        and verdict.injection_score >= settings.injection_threshold
    )
    return verdict


def system_prompts(messages: list[dict[str, Any]]) -> list[str]:
    texts: list[str] = []
    for m in messages:
        if m.get("role") in {"system", "developer"}:
            _map_text(m.get("content"), lambda t: texts.append(t) or t)
    return texts


def inspect_output(
    body: dict[str, Any], sys_prompts: list[str], settings: Settings
) -> OutputVerdict:
    body = copy.deepcopy(body)
    verdict = OutputVerdict(body=body)

    for choice in body.get("choices") or []:
        message = choice.get("message") or {}
        content = message.get("content")
        if not isinstance(content, str) or not content:
            continue

        redacted, secrets, blocking = output.scan(content, sys_prompts)
        verdict.findings.extend(secrets + blocking)

        if settings.output_action is OutputAction.FLAG:
            continue
        if blocking or (secrets and settings.output_action is OutputAction.BLOCK):
            message["content"] = REFUSAL
            choice["finish_reason"] = "content_filter"
            verdict.filtered = True
        elif secrets:
            message["content"] = redacted
            verdict.filtered = True

    return verdict
