"""Types shared by every guard."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum


class Stage(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a guard noticed. Never carries the matched text itself:
    findings go to the audit log, and a log must not become a second leak."""

    guard: str  # "injection" | "pii" | "output"
    rule: str  # stable rule id, e.g. "ignore_previous" or "EMAIL"
    stage: Stage
    message_index: int | None = None
    score: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "guard": self.guard,
            "rule": self.rule,
            "stage": self.stage.value,
            "message_index": self.message_index,
            "score": self.score,
        }


# Zero-width and bidi control characters are a classic way to split a keyword
# ("ig​nore") so that naive regexes miss it while the model still reads it.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Canonical form used for *detection only* (never for what we forward).

    NFKC folds full-width and stylised letters (``ｉｇｎｏｒｅ`` -> ``ignore``),
    invisible characters are dropped, case and whitespace are flattened.
    """
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return _WS.sub(" ", text).casefold().strip()
