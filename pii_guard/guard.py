"""Pre-emission protection for Python StreamHandler/FileHandler text outputs."""
import copy
import json
import logging
import os
from pathlib import Path
import tempfile
import threading
import time
from .detectors import ACTIVE_RULES, BUILTIN_RULES, detect, load_rules, redact

WITHHELD = '[logVeil: message withheld because protection could not complete]'


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class GuardPolicy:
    """One policy shared by installed handlers; rule updates load at next emission."""
    def __init__(self, rules_path=None, status_path=None, mode='mask'):
        if mode not in ('mask', 'block'):
            raise ValueError('Guard mode must be mask or block')
        configured = rules_path or os.environ.get('LOGVEIL_RULES') or os.environ.get('PII_GUARD_RULES')
        self.rules_path = Path(configured).resolve() if configured else None
        self.status_path = Path(status_path).resolve() if status_path else None
        if self.rules_path and self.status_path == self.rules_path:
            raise ValueError('Guard status must not overwrite the rule file')
        self.mode = mode
        self._signature = None
        self._rules = BUILTIN_RULES
        self.lock = threading.RLock()
        self.started_at = time.time()
        self.handlers = 0
        self.emissions = 0
        self.protected = 0
        self.errors = 0
        self.refresh()

    def refresh(self):
        if self.rules_path:
            stat = self.rules_path.stat()
            signature = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
            if signature != self._signature:
                rules = load_rules(self.rules_path)
                self._rules = rules
                self._signature = signature
        return self._rules

    def publish(self):
        if self.status_path:
            try:
                atomic_json(self.status_path, {'pid': os.getpid(), 'started_at': self.started_at,
                            'updated_at': time.time(), 'mode': self.mode, 'handlers': self.handlers,
                            'emissions': self.emissions, 'protected': self.protected, 'errors': self.errors})
            except OSError:
                # Telemetry failures never cause the original payload to be emitted.
                pass


class GuardFormatter(logging.Formatter):
    def __init__(self, inner, policy):
        super().__init__()
        self.inner = inner or logging.Formatter()
        self.policy = policy

    def format(self, record):
        policy = self.policy
        with policy.lock:
            token = None
            touched = False
            seen = set()

            def clean(value, key='', depth=0):
                nonlocal touched
                if depth > 12:
                    touched = True
                    return '[OMITTED]'
                if isinstance(value, (dict, list, tuple)):
                    if id(value) in seen:
                        touched = True
                        return '[OMITTED]'
                    seen.add(id(value))
                    try:
                        if isinstance(value, dict):
                            return {str(clean(str(k), depth=depth + 1)): clean(v, str(k), depth + 1) for k, v in value.items()}
                        return [clean(item, key, depth + 1) for item in value]
                    finally:
                        seen.remove(id(value))
                text = str(value)
                # Preserve context so numeric account fields are masked before JSON serialization.
                prefix = key + '=' if key else ''
                context = prefix + text
                if detect(context):
                    touched = True
                    cleaned = redact(context)
                    return cleaned[len(prefix):] if cleaned.startswith(prefix) else cleaned
                return value if isinstance(value, (str, int, float, bool, type(None))) else text

            try:
                token = ACTIVE_RULES.set(policy.refresh())
                sanitized = copy.copy(record)
                sanitized.msg = clean(record.getMessage())
                sanitized.args = ()
                for key, value in record.__dict__.items():
                    if key not in {'msg', 'args', 'exc_info', 'exc_text', 'stack_info', 'message'}:
                        setattr(sanitized, key, clean(value, key))
                sanitized.exc_info = None
                sanitized.exc_text = clean(self.inner.formatException(record.exc_info)) if record.exc_info else clean(record.exc_text)
                sanitized.stack_info = clean(record.stack_info)
                output = self.inner.format(sanitized)
                if detect(output):
                    touched = True
                    output = redact(output)
                if touched:
                    policy.protected += 1
                if touched and policy.mode == 'block':
                    output = '[logVeil: sensitive log message blocked]'
                return output
            except Exception:
                policy.errors += 1
                return WITHHELD
            finally:
                if token is not None:
                    ACTIVE_RULES.reset(token)
                policy.emissions += 1
                policy.publish()


def protect_handler(handler, policy):
    """Protect a standard text handler. Non-text handlers require an integration."""
    if not isinstance(handler, logging.StreamHandler):
        raise ValueError('Guard supports StreamHandler/FileHandler text outputs only')
    inner = handler.formatter
    if isinstance(inner, GuardFormatter):
        if inner.policy is policy:
            return handler
        inner = inner.inner
    handler.setFormatter(GuardFormatter(inner, policy))
    policy.handlers += 1
    policy.publish()
    return handler


def install_guard(rules_path=None, *, status_path=None, mode='mask', logger=None):
    """Call after logging configuration. Returns a policy for protecting later handlers."""
    target = logger or logging.getLogger()
    handlers = list(target.handlers)
    if logger is None:
        for item in logging.Logger.manager.loggerDict.values():
            if isinstance(item, logging.Logger):
                handlers.extend(item.handlers)
        if logging.lastResort:
            handlers.append(logging.lastResort)
    handlers = list(dict.fromkeys(handlers))
    if not handlers:
        raise ValueError('Configure logging handlers before installing the guard')
    if any(not isinstance(handler, logging.StreamHandler) for handler in handlers):
        raise ValueError('Guard requires text handlers; protect queue/network integrations separately')
    policy = GuardPolicy(rules_path, status_path, mode)
    for handler in handlers:
        protect_handler(handler, policy)
    return policy
