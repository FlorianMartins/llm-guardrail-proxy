"""Heuristic prompt-injection / jailbreak detector.

This is a *first line of defence*: cheap, deterministic, explainable, and
running in microseconds before any token is paid for. It will not stop a
determined attacker on its own (no pattern list can), which is why the
architecture keeps it behind a scoring interface: a classifier model can be
added as another scorer without touching the pipeline.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .base import Finding, Stage, normalize


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    weight: float


def _r(rule_id: str, pattern: str, weight: float) -> Rule:
    return Rule(rule_id, re.compile(pattern), weight)


# Patterns run on normalize()'d text: lower-case, single spaces, no invisibles.
# Weights are additive; the pipeline compares the sum with a threshold, so one
# strong signal blocks on its own while weak ones only count together.
RULES: tuple[Rule, ...] = (
    _r(
        "ignore_previous",
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}"
        r"\b(previous|prior|above|earlier|all|your|the|system)\b.{0,40}"
        r"\b(instructions?|prompts?|rules|directives|guidelines|context)\b",
        1.0,
    ),
    _r(
        "system_prompt_extraction",
        r"\b(reveal|show|print|repeat|output|display|tell me|give me|leak)\b.{0,40}"
        r"\b(system|hidden|initial|original|secret)\s+(prompt|instructions?|message)",
        0.9,
    ),
    _r(
        "role_override",
        r"\b(you are now|from now on,? you are|act as|pretend (to be|you are)|roleplay as)\b"
        r".{0,60}\b(dan|unfiltered|uncensored|jailbroken|no (rules|restrictions|limits)"
        r"|developer mode|evil)\b",
        1.0,
    ),
    _r("dan_jailbreak", r"\b(do anything now|dan mode|developer mode (enabled|on))\b", 1.0),
    _r(
        "fake_system_turn",
        # Chat-template tokens or a forged header smuggled inside user content.
        r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<<sys>>"
        r"|^#{1,3} ?system\b|\bsystem ?(prompt|message)? ?:\s)",
        0.8,
    ),
    _r(
        "disable_safety",
        r"\b(disable|turn off|remove|ignore|without)\b.{0,30}"
        r"\b(safety|guardrails?|filters?|content policy|restrictions|censorship)\b",
        0.6,
    ),
    _r("new_instructions", r"\b(new|updated|real|actual) (instructions|rules|task) ?:", 0.5),
    _r("prompt_delimiter_escape", r"(-{5,}|={5,}|#{5,}) ?(end|begin|new)\b", 0.3),
)

# Long base64 runs are how payloads get smuggled past keyword filters.
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _decoded_payloads(raw: str) -> list[str]:
    out: list[str] = []
    for candidate in _B64.findall(raw)[:5]:  # bounded work per message
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def scan(text: str, message_index: int | None = None) -> tuple[float, list[Finding]]:
    """Return (total score, findings) for one message."""
    findings: list[Finding] = []
    seen: set[str] = set()

    def _match(haystack: str, suffix: str = "") -> None:
        norm = normalize(haystack)
        for rule in RULES:
            rid = rule.id + suffix
            if rid not in seen and rule.pattern.search(norm):
                seen.add(rid)
                findings.append(Finding("injection", rid, Stage.INPUT, message_index, rule.weight))

    _match(text)
    for payload in _decoded_payloads(text):
        _match(payload, suffix=":base64")

    return sum(f.score for f in findings), findings
