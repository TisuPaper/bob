import ast
import hashlib
import json
from pathlib import Path
from .detectors import detect

LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal"}
SKIP = {".git", ".venv", "venv", "__pycache__", "node_modules", ".demo"}


def logging_calls(tree):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in LEVELS and node.args
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"logger", "logging", "log"}):
            yield node


def python_files(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    return [path] if path.is_file() else sorted(
        p for p in path.rglob("*.py") if not any(part in SKIP for part in p.relative_to(path).parts)
    )


def static_scan(path):
    findings = []
    for file in python_files(path):
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        for node in logging_calls(tree):
            dynamic = len(node.args) > 1 or not isinstance(node.args[0], ast.Constant)
            literal = isinstance(node.args[0], ast.Constant) and bool(detect(str(node.args[0].value)))
            exception = node.func.attr == "exception" or any(k.arg == "exc_info" for k in node.keywords)
            if dynamic or literal or exception:
                findings.append({"origin": "static", "source": str(file), "line": node.lineno,
                                 "kind": "LOG_RISK", "confidence": "heuristic",
                                 "path": "dynamic value / object / exception → logging call",
                                 "suggestion": "Redact the fully formatted message and exception before emitting."})
    return findings


def log_text(value, key=""):
    if isinstance(value, dict):
        return "\n".join(log_text(v, str(k)) for k, v in value.items())
    if isinstance(value, list):
        return "\n".join(log_text(v, key) for v in value)
    return f"{key}={value}"


def log_scan(path):
    findings = []
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            source, source_line, message = None, None, raw.rstrip("\n")
            try:
                record = json.loads(raw)
                if isinstance(record, dict):
                    # Scan the entire record, including structured extras.
                    message = log_text(record)
                    if isinstance(record.get("source"), str) and type(record.get("line")) is int and record["line"] > 0:
                        source, source_line = record["source"], record["line"]
            except json.JSONDecodeError:
                pass
            for match in detect(message):
                findings.append({"origin": "runtime", "log": str(path), "log_line": line_number,
                                 "source": source, "line": source_line, "kind": match.kind,
                                 "masked": match.masked, "confidence": "observed-pattern",
                                 "path": "logging call → captured log" if source else "captured log → source unknown",
                                 "suggestion": "Mask at the logging call; rerun tests and scan fresh logs."})
    return findings


def fingerprint(finding):
    # No PII or PII-derived hashes in baselines. Locations are intentionally line-sensitive.
    key = [finding["origin"], finding.get("source") or finding.get("log"),
           finding.get("line") or finding.get("log_line"), finding["kind"]]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]
