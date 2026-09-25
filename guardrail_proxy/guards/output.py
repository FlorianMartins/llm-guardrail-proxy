"""Validation of the model's answer before it reaches the client.

Three independent checks:

* **Secret leakage**: credentials, keys, card numbers, IBANs in the answer
  (e.g. a RAG corpus or tool result that contained a secret). E-mails and
  phone numbers are *not* treated as leaks here, since answers legitimately
  contain them ("write to support@...").
* **Dangerous instructions**: destructive or remote-code-execution commands
  a user could copy-paste (``rm -rf /``, ``curl | sh``, reverse shells...).
* **System-prompt leakage**: the answer quotes a sizeable verbatim chunk of
  the system prompt, which is the goal of most extraction attacks.
"""

from __future__ import annotations

import re

from . import pii
from .base import Finding, Stage, normalize

LEAK_DETECTORS: tuple[pii.Detector, ...] = tuple(
    d
    for d in pii.DETECTORS
    if d.label in {"PRIVATE_KEY", "API_KEY", "JWT", "SECRET", "CREDIT_CARD", "IBAN"}
)

DANGEROUS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule_id, re.compile(p, re.IGNORECASE))
    for rule_id, p in (
        (
            "destructive_rm",
            r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force)"
            r"[a-z]*\s+(/|~|\$home|/\*|--no-preserve-root)(\s|$|\*)",
        ),
        ("disk_wipe", r"\b(mkfs(\.\w+)?\s+/dev/|dd\s+if=\S+\s+of=/dev/(sd|nvme|hd|disk))"),
        ("fork_bomb", r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        ("pipe_to_shell", r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
        (
            "reverse_shell",
            r"(/dev/tcp/\d|\bnc(at)?\s+(-\w+\s+)*-e\s+/bin/(ba)?sh"
            r"|socket\.socket\(.*subprocess)",
        ),
        (
            "powershell_download_exec",
            r"(iex|invoke-expression)\s*\(?\s*\(?\s*(new-object\s+net\."
            r"webclient|iwr|invoke-webrequest)",
        ),
        (
            "encoded_powershell",
            r"\bpowershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[a-z0-9+/=]{20,}",
        ),
        ("disable_av", r"set-mppreference\s+-disable(realtimemonitoring|ioavprotection)\s+\$?true"),
        ("world_writable_root", r"\bchmod\s+(-r\s+)?777\s+/(\s|$)"),
    )
)

_SENTENCE = re.compile(r"(?<=[.!?\n])\s+")
_MIN_LEAK_CHARS = 40


def _system_leak(answer_norm: str, system_prompts: list[str]) -> bool:
    for prompt in system_prompts:
        for chunk in _SENTENCE.split(prompt):
            chunk = normalize(chunk)
            if len(chunk) >= _MIN_LEAK_CHARS and chunk in answer_norm:
                return True
    return False


def scan(answer: str, system_prompts: list[str]) -> tuple[str, list[Finding], list[Finding]]:
    """Return (answer with secrets masked, secret findings, blocking findings).

    *Secret* findings can be fixed by redaction; *blocking* findings cannot
    (half a reverse shell is still a reverse shell), so the caller decides
    between refusing and forwarding.
    """
    redacted, secret_findings = pii.redact(answer, Stage.OUTPUT, detectors=LEAK_DETECTORS)
    secret_findings = [Finding("output", f.rule, f.stage, None, f.score) for f in secret_findings]

    blocking: list[Finding] = []
    for rule_id, pattern in DANGEROUS:
        if pattern.search(answer):
            blocking.append(Finding("output", rule_id, Stage.OUTPUT, None, 1.0))
    if system_prompts and _system_leak(normalize(answer), system_prompts):
        blocking.append(Finding("output", "system_prompt_leak", Stage.OUTPUT, None, 1.0))

    return redacted, secret_findings, blocking
