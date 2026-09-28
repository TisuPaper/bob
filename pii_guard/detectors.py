"""Conservative format detectors; matches are candidates, not identity validation."""
import re
import json
import os
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
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


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: re.Pattern
    group: str | None = None
    keep_last: int = 0
    priority: int = 100
    validator: str | None = None


BUILTIN_RULES = tuple(
    Rule(kind, pattern, "value" if kind == "ACCOUNT" else None,
         0 if kind == "EMAIL" else 4, 200 if kind == "ACCOUNT" else 100,
         "luhn" if kind == "CARD" else None)
    for kind, pattern in PATTERNS
)
ACTIVE_RULES = ContextVar("pii_guard_rules", default=None)


def load_rules(path):
    """Load an additive, versioned JSON rule set; reject ambiguous configuration."""
    return parse_rules(json.loads(Path(path).read_text(encoding="utf-8")))


def parse_rules(data):
    """Validate a decoded configuration before it is used or saved."""
    if not isinstance(data, dict) or set(data) != {"version", "rules"}:
        raise ValueError("Expected version and rules fields")
    if type(data["version"]) is not int or data["version"] != 1 or not isinstance(data["rules"], list):
        raise ValueError("Unsupported rule schema")
    rules = list(BUILTIN_RULES)
    names = {rule.kind for rule in rules}
    for item in data["rules"]:
        if not isinstance(item, dict) or set(item) - {"kind", "pattern", "group", "keep_last", "priority", "validator"}:
            raise ValueError("Unknown rule fields")
        kind, pattern = item.get("kind"), item.get("pattern")
        if not isinstance(kind, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}", kind) or kind in names:
            raise ValueError("Invalid or duplicate rule kind")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("Rule needs a regex pattern")
        try:
            compiled = re.compile(pattern)
        except re.error:
            raise ValueError("Invalid rule regex") from None
        group = item.get("group")
        if group is not None and (not isinstance(group, str) or group not in compiled.groupindex):
            raise ValueError("Group must name a regex capture")
        keep, priority = item.get("keep_last", 0), item.get("priority", 200)
        if type(keep) is not int or not 0 <= keep <= 4 or type(priority) is not int:
            raise ValueError("Invalid masking or priority setting")
        validator = item.get("validator")
        if validator not in (None, "luhn") or compiled.search("") is not None:
            raise ValueError("Invalid validator or empty-matching regex")
        rules.append(Rule(kind, compiled, group, keep, priority, validator))
        names.add(kind)
    return tuple(rules)


@lru_cache(maxsize=16)
def _environment_rules(path):
    return load_rules(path)


def get_rules():
    active = ACTIVE_RULES.get()
    if active is not None:
        return active
    path = os.environ.get("PII_GUARD_RULES")
    return _environment_rules(str(Path(path).resolve())) if path else BUILTIN_RULES


def detect(text):
    candidates = []
    for rule in sorted(get_rules(), key=lambda rule: -rule.priority):
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.group) if rule.group else match.span()
            if start < 0 or start == end:
                continue
            value = text[start:end]
            if rule.validator == "luhn" and not luhn(value):
                continue
            if any(start < m.end and end > m.start for m in candidates):
                continue
            masked = (f"[{rule.kind} ****{value[-rule.keep_last:]}]"
                      if rule.keep_last and len(value) > rule.keep_last
                      else f"[{rule.kind} REDACTED]")
            candidates.append(Match(rule.kind, start, end, masked))
    return sorted(candidates, key=lambda m: m.start)


def redact(text):
    for match in reversed(detect(text)):
        text = text[:match.start] + match.masked + text[match.end:]
    return text
