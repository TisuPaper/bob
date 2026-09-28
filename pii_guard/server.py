"""Loopback report server with a validated custom-rules editor."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit
from .detectors import parse_rules
from .rules_editor import editor_html, save_rules


def report_server(path, port=8000, rules_path='rules/custom.json'):
    report = Path(path).resolve()
    report.read_bytes()
    rules = Path(rules_path).resolve()
    token = secrets.token_urlsafe(32)
    lock = threading.Lock()
    if not 0 <= port <= 65535:
        raise ValueError('Port must be between 0 and 65535')

    def read_config():
        raw = rules.read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def allowed_host(self):
            return self.headers.get('Host') in {
                f'localhost:{self.server.server_port}', f'127.0.0.1:{self.server.server_port}'}

        def send_content(self, content, content_type, status=200, body=True):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            if body:
                self.wfile.write(content)

        def json_response(self, data, status=200, body=True):
            self.send_content(json.dumps(data).encode(), 'application/json', status, body)

        def do_GET(self):
            self.respond(body=True)

        def do_HEAD(self):
            self.respond(body=False)

        def respond(self, body):
            if not self.allowed_host():
                self.send_error(403)
                return
            route = urlsplit(self.path).path
            try:
                if route == '/api/rules':
                    with lock:
                        data, revision = read_config()
                    self.json_response({'config': data, 'revision': revision}, body=body)
                    return
                if route == '/rules':
                    content = editor_html(token)
                elif route in {'/', '/report.html'}:
                    content = report.read_bytes().replace(b'<body>', b'<body><nav style="padding:12px 24px;background:#e7f4f0"><a href="/rules">Edit custom detection rules</a></nav>', 1)
                else:
                    self.send_error(404)
                    return
            except (OSError, ValueError):
                self.json_response({'error': 'File unavailable or invalid JSON. Check the configured report/rules file.'}, 404, body)
                return
            self.send_content(content, 'text/html; charset=utf-8', body=body)

        def do_POST(self):
            if not self.allowed_host() or not secrets.compare_digest(self.headers.get('X-PII-Token', ''), token):
                self.json_response({'error': 'Request not authorised. Reload the editor.'}, 403)
                return
            route = urlsplit(self.path).path
            if route not in {'/api/rules/validate', '/api/rules/save'}:
                self.send_error(404)
                return
            if self.headers.get('Content-Type') != 'application/json':
                self.json_response({'error': 'Expected application/json.'}, 415)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 262144:
                    self.json_response({'error': 'Configuration must be between 1 byte and 256 KiB.'}, 413)
                    return
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict) or 'config' not in payload:
                    raise ValueError('Expected a configuration object')
                parse_rules(payload['config'])
                with lock:
                    if route.endswith('/save'):
                        _, revision = read_config()
                        if payload.get('revision') != revision:
                            self.json_response({'error': 'Rules changed since loading. Copy your draft and reload before saving.'}, 409)
                            return
                        save_rules(rules, payload['config'])
                        _, revision = read_config()
                        self.json_response({'ok': True, 'revision': revision})
                    else:
                        self.json_response({'ok': True})
            except json.JSONDecodeError:
                self.json_response({'error': 'Invalid JSON. Check quotes, commas and escaped backslashes.'}, 400)
            except (ValueError, UnicodeError):
                self.json_response({'error': 'Invalid rules. Check schema version, unique uppercase names, regex syntax, groups, keep_last (0–4), priority and validator.'}, 400)
            except OSError:
                self.json_response({'error': 'Could not read or save the configured rules file.'}, 500)

        def log_message(self, format, *args):
            pass

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def serve(path, port=8000, rules_path='rules/custom.json'):
    with report_server(path, port, rules_path) as server:
        print(f'Open report: http://localhost:{server.server_port}/', flush=True)
        print(f'Edit rules: http://localhost:{server.server_port}/rules', flush=True)
        print('Press Ctrl+C to stop. Regenerate the report and refresh to see updates.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nReport server stopped.')
    return 0
