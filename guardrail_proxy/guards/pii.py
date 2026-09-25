"""PII and secret detection / redaction.

Each detector is a regex plus an optional validator, so that a 16-digit order
number is not mistaken for a credit card (Luhn) and a random word is not
mistaken for an IP. The same detectors are reused on the *output* side to
catch data the model leaks back.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

from .base import Finding, Stage


def _luhn_ok(match: str) -> bool:
    digits = [int(c) for c in match if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_ok(match: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(match)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _iban_ok(match: str) -> bool:
    s = match.replace(" ", "").upper()
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


@dataclass(frozen=True, slots=True)
class Detector:
    label: str  # placeholder becomes [REDACTED_<label>]
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None
    # When the pattern has a named group "v", only that group is redacted
    # (keeps "password=" readable, masks the value).


# Order matters: specific secrets first, so an API key embedded in a URL is
# labelled API_KEY rather than being partly eaten by a broader pattern.
DETECTORS: tuple[Detector, ...] = (
    Detector(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----"
        ),
    ),
    Detector(
        "API_KEY",
        re.compile(
            r"\b(?:"
            r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"  # OpenAI / Anthropic
            r"|AKIA[0-9A-Z]{16}"  # AWS access key id
            r"|gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub tokens
            r"|github_pat_[A-Za-z0-9_]{50,}"
            r"|xox[abprs]-[A-Za-z0-9-]{10,}"  # Slack
            r"|AIza[0-9A-Za-z_\-]{35}"  # Google API key
            r"|hf_[A-Za-z0-9]{30,}"  # Hugging Face
            r")"
        ),
    ),
    Detector("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    Detector(
        "SECRET",
        # key=value style credentials: password=..., api_key: "...", token=...
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token)"
            r"[\"']?\s*[:=]\s*[\"']?(?P<v>[^\s\"',;]{6,})"
        ),
    ),
    Detector("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), _luhn_ok),
    Detector(
        "IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), _iban_ok
    ),
    Detector(
        "PHONE", re.compile(r"(?<![\w+])\+\d{1,3}[ .-]?(?:\(?\d{1,4}\)?[ .-]?){2,5}\d{2,4}\b")
    ),
    Detector("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), _ipv4_ok),
)


def redact(
    text: str,
    stage: Stage,
    message_index: int | None = None,
    detectors: tuple[Detector, ...] = DETECTORS,
) -> tuple[str, list[Finding]]:
    """Replace every detected entity with ``[REDACTED_<LABEL>]``."""
    findings: list[Finding] = []
    for det in detectors:
        hits = 0

        def _sub(m: re.Match[str], det: Detector = det) -> str:
            nonlocal hits
            whole = m.group(0)
            target = m.group("v") if "v" in m.re.groupindex else whole
            if target.startswith("[REDACTED_"):  # already masked by an earlier detector
                return whole
            if det.validate and not det.validate(whole):
                return whole
            hits += 1
            placeholder = f"[REDACTED_{det.label}]"
            if "v" in m.re.groupindex:
                start, end = m.span("v")
                base = m.start()
                return whole[: start - base] + placeholder + whole[end - base :]
            return placeholder

        text = det.pattern.sub(_sub, text)
        if hits:
            findings.append(Finding("pii", det.label, stage, message_index, float(hits)))
    return text, findings
