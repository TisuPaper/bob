import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from pii_guard.rules_editor import save_rules
from pii_guard.server import report_server


class EditorTests(unittest.TestCase):
    def test_invalid_save_preserves_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            original = '{"version": 1, "rules": []}\n'
            path.write_text(original)
            with self.assertRaises(ValueError):
                save_rules(path, {'version': 1, 'rules': [{'kind': 'BAD', 'pattern': '('}]})
            self.assertEqual(path.read_text(), original)
            data = {'version': 1, 'rules': [{'kind': 'EMPLOYEE', 'pattern': 'EMP-[0-9]{6}'}]}
            save_rules(path, data)
            self.assertEqual(json.loads(path.read_text()), data)

    def test_http_editor_validation_save_and_conflict(self):
        # Exercise the real HTTP handler with in-memory sockets; no listening port needed.
        class Socket:
            def __init__(self, request):
                self.request = io.BytesIO(request)
                self.response = io.BytesIO()
            def makefile(self, *args):
                return self.request
            def sendall(self, data):
                self.response.write(data)

        with tempfile.TemporaryDirectory() as d:
            report, rules = Path(d) / 'report.html', Path(d) / 'rules.json'
            report.write_text('<html><body>Report</body></html>')
            rules.write_text('{"version":1,"rules":[]}')
            with patch('pii_guard.server.ThreadingHTTPServer') as factory:
                report_server(report, 8000, rules, root=d)
                handler = factory.call_args.args[1]
            server = type('Server', (), {'server_port': 8000})()

            def request(path, payload=None, token=None, host='localhost:8000'):
                method = 'GET' if payload is None else 'POST'
                body = b'' if payload is None else json.dumps(payload).encode()
                headers = f'{method} {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                if token:
                    headers += f'X-PII-Token: {token}\r\n'
                socket = Socket(headers.encode() + b'\r\n' + body)
                handler(socket, ('127.0.0.1', 12345), server)
                response = socket.response.getvalue()
                head, content = response.split(b'\r\n\r\n', 1)
                return int(head.split()[1]), content

            status, page = request('/rules')
            self.assertEqual(status, 200)
            token = re.search(rb'const token="([^"]+)"', page).group(1).decode()
            self.assertIn(b'/rules', request('/')[1])
            self.assertEqual(request('/api/state')[0], 200)
            self.assertIn(b'Scan results', request('/')[1])
            self.assertEqual(request('/assets/app.js')[0], 200)
            self.assertEqual(request('/api/scan', {'paths': ['../outside'], 'mode': 'logs'}, token)[0], 400)
            self.assertEqual(request('/api/rules', host='untrusted.test')[0], 403)
            self.assertEqual(request('/../rules.json')[0], 404)
            config = json.loads(request('/api/rules')[1])
            config['config']['rules'].append({'kind': 'EMPLOYEE', 'pattern': 'EMP-[0-9]{6}'})
            self.assertEqual(request('/api/rules/save', config)[0], 403)
            self.assertEqual(request('/api/rules/validate', config, token)[0], 200)
            status, preview = request('/api/rules/test', {'config': config['config'], 'sample': 'EMP-123456'}, token)
            self.assertEqual(status, 200)
            self.assertNotIn(b'EMP-123456', preview)
            self.assertEqual(json.loads(preview)['count'], 1)
            self.assertEqual(json.loads(rules.read_text())['rules'], [])
            self.assertEqual(request('/api/rules/save', config, token)[0], 200)
            self.assertEqual(json.loads(rules.read_text()), config['config'])
            self.assertEqual(request('/api/rules/save', config, token)[0], 409)
            saved = rules.read_text()
            self.assertEqual(request('/api/rules/save', {'config': {'version': 99, 'rules': []}}, token)[0], 400)
            self.assertEqual(rules.read_text(), saved)


if __name__ == '__main__':
    unittest.main()
