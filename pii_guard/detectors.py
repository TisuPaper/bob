"""Conservative format detectors; matches are candidates, not identity validation."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    kind: str
    start: int
    end: int
    masked: str


def luhn(value):
    digits = [int(c) for c in value if c.isdigit()]
    return len(set(digits)) > 1 and sum(
        (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d
        for i, d in enumerate(reversed(digits))
    ) % 10 == 0


PATTERNS = [
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")),
    ("MY_IC", re.compile(r"(?<!\d)\d{6}-\d{2}-\d{4}(?!\d)|(?<!\d)\d{12}(?!\d)")),
    ("CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
    ("ACCOUNT", re.compile(r"(?i)\b(?:account(?:_number|_no)?|acct)[\"']?\s*[:=]\s*[\"']?(?P<value>\d{8,18})(?!\d)")),
]


def detect(text):
    candidates = []
    # Contextual account numbers take precedence over generic numeric formats.
    for kind, pattern in sorted(PATTERNS, key=lambda p: p[0] != "ACCOUNT"):
        for match in pattern.finditer(text):
            start, end = match.span("value") if kind == "ACCOUNT" else match.span()
            value = text[start:end]
            if kind == "CARD" and not luhn(value):
                continue
            if any(start < m.end and end > m.start for m in candidates):
                continue
            masked = "[EMAIL REDACTED]" if kind == "EMAIL" else f"[{kind} ****{value[-4:]}]"
            candidates.append(Match(kind, start, end, masked))
    return sorted(candidates, key=lambda m: m.start)


def redact(text):
    for match in reversed(detect(text)):
        text = text[:match.start] + match.masked + text[match.end:]
    return text
