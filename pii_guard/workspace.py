"""Thread-safe local workspace state; browser scans are confined to one root."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
from .detectors import ACTIVE_RULES, load_rules, parse_rules, redact
from .guard import atomic_json
from .inputs import discover
from .scanner import log_scan, static_scan
from .web_report import write_html


def masked_data(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: masked_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [masked_data(item) for item in value]
    return value


def result_path(report):
    return Path(str(report) + '.json')


def save_result(report, findings, summary):
    result = masked_data({'created_at': datetime.now(timezone.utc).isoformat(),
                          'summary': summary, 'findings': findings})
    atomic_json(result_path(report), result)
    return result


class Workspace:
    def __init__(self, root, report, rules, status_path=None):
        self.root = Path(root).resolve()
        self.report = Path(report).resolve()
        self.rules = Path(rules).resolve()
        self.status_path = Path(status_path).resolve() if status_path else self.root / '.logveil/guard-status.json'
        if len({self.report, self.rules, self.status_path, result_path(self.report)}) != 4:
            raise ValueError('Report, rules and status paths must be distinct')
        if not self.rules.exists():
            atomic_json(self.rules, {'version': 1, 'rules': []})
        self.lock = threading.RLock()
        self.running = False
        self.error = None
        self.result = None
        self._result_signature = None

    def read_rules(self):
        if not self.rules.exists():
            return {'version': 1, 'rules': []}, 'missing'
        raw = self.rules.read_bytes()
        data = json.loads(raw)
        parse_rules(data)
        return data, hashlib.sha256(raw).hexdigest()

    def snapshot(self):
        with self.lock:
            try:
                file = result_path(self.report)
                stamp = file.stat().st_mtime_ns
                if stamp != self._result_signature:
                    data = json.loads(file.read_text(encoding='utf-8'))
                    if isinstance(data, dict) and isinstance(data.get('findings'), list) and isinstance(data.get('summary'), dict):
                        self.result = data
                        self._result_signature = stamp
            except (OSError, ValueError):
                pass
            guard = None
            try:
                data = json.loads(self.status_path.read_text(encoding='utf-8'))
                numeric = ('updated_at', 'handlers', 'emissions', 'protected', 'errors')
                if all(type(data.get(key)) in (int, float) for key in numeric) and data.get('mode') in ('mask', 'block'):
                    guard = {key: data[key] for key in numeric + ('mode',)}
            except (OSError, ValueError, AttributeError):
                pass
            setup = ('from pii_guard.guard import install_guard\n\n'
                     '# Call after configuring logging handlers.\n'
                     'policy = install_guard(\n'
                     f'    rules_path={str(self.rules)!r},\n'
                     f'    status_path={str(self.status_path)!r},\n'
                     '    mode="mask",\n)')
            return {'workspace': str(self.root), 'result': self.result,
                    'scan': {'running': self.running, 'error': self.error}, 'guard': guard,
                    'setup': setup, 'report_available': self.report.is_file()}

    def start_scan(self, paths, mode):
        if not isinstance(paths, list) or not paths or len(paths) > 20 or any(not isinstance(path, str) or not path.strip() for path in paths):
            raise ValueError('Enter a file or directory inside this workspace')
        if mode not in ('auto', 'logs', 'python'):
            raise ValueError('Choose a supported scan type')
        resolved = []
        for value in paths:
            path = (self.root / value).resolve()
            if not path.is_relative_to(self.root):
                raise ValueError('Select a path inside the workspace; change --root to scan another project')
            resolved.append((path, mode))
        with self.lock:
            if self.running:
                raise ValueError('A scan is already running')
            self.running, self.error = True, None
        thread = threading.Thread(target=self._scan, args=(resolved,), daemon=True)
        thread.start()
        return thread

    def _scan(self, requests):
        token = None
        try:
            with self.lock:
                config, _ = self.read_rules()
            token = ACTIVE_RULES.set(parse_rules(config))
            files, skipped = discover(requests, ignored=[self.rules, self.report, result_path(self.report), self.status_path, self.root / 'logveil.json'])
            summary = {'files_scanned': len(files), 'streams_scanned': 0, 'log_lines': 0, 'skipped_files': skipped}
            findings = []
            for file, mode in files:
                findings.extend(static_scan(file) if mode == 'python' else log_scan(file, summary))
            self.report.parent.mkdir(parents=True, exist_ok=True)
            write_html(self.report, findings, summary=summary)
            result = save_result(self.report, findings, summary)
            with self.lock:
                self.result = result
        except Exception:
            with self.lock:
                self.error = 'Scan incomplete. Check the path, rules, file permissions, encoding and input limits. Previous results are unchanged.'
        finally:
            if token is not None:
                ACTIVE_RULES.reset(token)
            with self.lock:
                self.running = False
