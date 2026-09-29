"""Local UI and APIs. Mutations require a session token; scans stay inside a root."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit
from .detectors import ACTIVE_RULES, detect, parse_rules, redact
from .rules_editor import save_rules
from .workspace import Workspace


def report_server(path, port=8000, rules_path='rules/custom.json', root=None, status_path=None):
    if not 0 <= port <= 65535:
        raise ValueError('Port must be between 0 and 65535')
    workspace = Workspace(root or Path.cwd(), path, rules_path, status_path)
    token = secrets.token_urlsafe(32)
    assets = files('pii_guard').joinpath('assets')

    class Handler(BaseHTTPRequestHandler):
        def allowed_host(self):
            allowed = {f'localhost:{self.server.server_port}', f'127.0.0.1:{self.server.server_port}'}
            origin = self.headers.get('Origin')
            return self.headers.get('Host') in allowed and (not origin or origin in {f'http://{host}' for host in allowed})

        def send_content(self, content, content_type, status=200, body=True):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
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
                    with workspace.lock:
                        data, revision = workspace.read_rules()
                    self.json_response({'config': data, 'revision': revision}, body=body)
                    return
                if route == '/api/state':
                    self.json_response(workspace.snapshot(), body=body)
                    return
                if route in {'/', '/rules', '/protection'}:
                    content = assets.joinpath('app.html').read_text(encoding='utf-8').replace('__TOKEN__', json.dumps(token)).encode()
                    content_type = 'text/html; charset=utf-8'
                elif route in {'/assets/app.css', '/assets/app.js'}:
                    content = assets.joinpath(route.rsplit('/', 1)[1]).read_bytes()
                    content_type = 'text/css' if route.endswith('.css') else 'text/javascript'
                elif route == '/report.html':
                    content = workspace.report.read_bytes()
                    content_type = 'text/html; charset=utf-8'
                else:
                    self.send_error(404)
                    return
            except (OSError, ValueError):
                self.json_response({'error': 'File unavailable or invalid rules. Check the selected files.'}, 404, body)
                return
            self.send_content(content, content_type, body=body)

        def do_POST(self):
            if not self.allowed_host() or not secrets.compare_digest(self.headers.get('X-PII-Token', ''), token):
                self.json_response({'error': 'Request not authorised. Reload the workspace.'}, 403)
                return
            route = urlsplit(self.path).path
            if route not in {'/api/rules/validate', '/api/rules/save', '/api/rules/test', '/api/scan'}:
                self.send_error(404)
                return
            if self.headers.get('Content-Type') != 'application/json':
                self.json_response({'error': 'Expected application/json.'}, 415)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 262144:
                    self.json_response({'error': 'Request must be between 1 byte and 256 KiB.'}, 413)
                    return
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('Expected an object')
                if route == '/api/scan':
                    try:
                        workspace.start_scan(payload.get('paths'), payload.get('mode', 'auto'))
                    except ValueError as exc:
                        self.json_response({'error': str(exc)}, 400)
                        return
                    self.json_response({'ok': True}, 202)
                    return
                compiled = parse_rules(payload.get('config'))
                if route == '/api/rules/test':
                    sample = payload.get('sample')
                    if not isinstance(sample, str) or len(sample) > 8192:
                        raise ValueError('Invalid sample')
                    active = ACTIVE_RULES.set(compiled)
                    try:
                        matches = detect(sample)
                        self.json_response({'masked': redact(sample), 'count': len(matches), 'kinds': sorted({m.kind for m in matches})})
                    finally:
                        ACTIVE_RULES.reset(active)
                    return
                with workspace.lock:
                    if route.endswith('/save'):
                        _, revision = workspace.read_rules()
                        if payload.get('revision') != revision:
                            self.json_response({'error': 'Rules changed since loading. Copy your draft and reload before saving.'}, 409)
                            return
                        workspace.rules.parent.mkdir(parents=True, exist_ok=True)
                        save_rules(workspace.rules, payload['config'])
                        _, revision = workspace.read_rules()
                        self.json_response({'ok': True, 'revision': revision})
                    else:
                        self.json_response({'ok': True})
            except json.JSONDecodeError:
                self.json_response({'error': 'Invalid JSON. Check quotes, commas and escaped backslashes.'}, 400)
            except (ValueError, UnicodeError, RecursionError):
                self.json_response({'error': 'Invalid rules or sample. Check unique uppercase names, regex syntax, capture groups and masking options.'}, 400)
            except OSError:
                self.json_response({'error': 'Could not read or save the selected rules file.'}, 500)

        def log_message(self, format, *args):
            pass

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def serve(path, port=8000, rules_path='rules/custom.json', root=None, status_path=None):
    with report_server(path, port, rules_path, root, status_path) as server:
        print(f'Open workspace: http://localhost:{server.server_port}/', flush=True)
        print(f'Protection setup: http://localhost:{server.server_port}/protection', flush=True)
        print('Press Ctrl+C to stop.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nWorkspace stopped.')
    return 0
