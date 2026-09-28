import ast
import gzip
import re
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


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAX_LINE_BYTES = 1024 * 1024


def scan_line(raw, path, line_number):
    source, source_line = None, None
    message = ANSI.sub("", raw.rstrip("\r\n"))
    if "\x00" in message:
        raise ValueError("Binary input is not supported")
    try:
        record = json.loads(message)
        message = log_text(record)
        if isinstance(record, dict):
            source = record.get("source", record.get("pathname"))
            source_line = record.get("line", record.get("lineno"))
            if not isinstance(source, str) or type(source_line) is not int or source_line < 1:
                source, source_line = None, None
    except json.JSONDecodeError:
        pass
    findings = []
    for match in detect(message):
        findings.append({"origin": "runtime", "log": str(path), "log_line": line_number,
                         "source": source, "line": source_line, "kind": match.kind,
                         "masked": match.masked, "confidence": "observed-pattern",
                         "path": "logging call → captured log" if source else "captured log → source unknown",
                         "suggestion": "Mask at the logging call; rerun tests and scan fresh logs."})
    return findings


def scan_stream(stream, label, stats=None):
    findings, line_number = [], 0
    while True:
        raw = stream.readline(MAX_LINE_BYTES + 1)
        if not raw:
            break
        if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError("Input line exceeds the 1 MiB limit; scan incomplete")
        line_number += 1
        findings.extend(scan_line(raw, label, line_number))
    if stats is not None:
        stats['log_lines'] = stats.get('log_lines', 0) + line_number
    return findings


MAX_JSON_BYTES = 16 * 1024 * 1024


def log_scan(path, stats=None):
    compressed = str(path).lower().endswith('.gz')
    opener = gzip.open if compressed else open
    with opener(path, 'rt', encoding='utf-8-sig') as stream:
        name = str(path)[:-3] if compressed else str(path)
        if name.lower().endswith('.json'):
            raw = stream.read(MAX_JSON_BYTES + 1)
            if len(raw.encode('utf-8')) > MAX_JSON_BYTES:
                raise ValueError('JSON document exceeds 16 MiB; export JSONL for larger inputs')
            data = json.loads(raw)
            findings = []
            records = data if isinstance(data, list) else [data]
            for index, record in enumerate(records):
                matches = scan_line(json.dumps(record, ensure_ascii=False), path, None)
                for finding in matches:
                    finding['json_pointer'] = f'/{index}' if isinstance(data, list) else ''
                findings.extend(matches)
            if stats is not None:
                stats['log_lines'] = stats.get('log_lines', 0) + len(raw.splitlines())
            return findings
        return scan_stream(stream, str(path), stats)


def log_location(finding):
    if 'json_pointer' in finding:
        return f"{finding['log']} (JSON pointer {finding['json_pointer'] or '/'})"
    return f"{finding['log']}:{finding['log_line']}"


def fingerprint(finding):
    # No PII or PII-derived hashes in baselines. Locations are intentionally line-sensitive.
    key = [finding["origin"], finding.get("source") or finding.get("log"),
           finding.get("line") or finding.get("log_line") or finding.get("json_pointer"), finding["kind"]]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]
