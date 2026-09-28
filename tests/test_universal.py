import contextlib
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from pii_guard.cli import main
from pii_guard.config import load_config
from pii_guard.runner import scan_command
from pii_guard.scanner import log_scan


class UniversalTests(unittest.TestCase):
    def invoke(self, args, stdin=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with patch('sys.stdin', io.StringIO(stdin or '')):
                code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_recursive_mixed_inputs_exclusions_and_gzip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'app.py').write_text('logger.info("%s", customer)')
            (root / 'app.log').write_text('person@example.test\n')
            (root / 'empty.log').write_text('OK\n')
            (root / 'ignore.log').write_text('ignored@example.test\n')
            (root / 'image.png').write_bytes(b'\x00binary')
            (root / 'node_modules').mkdir()
            (root / 'node_modules' / 'ignored.log').write_text('ignored@example.test\n')
            with gzip.open(root / 'server.log.1.gz', 'wt') as stream:
                stream.write('account=1234567890\n')
            code, out, _ = self.invoke(['scan', str(root), '--exclude', 'ignore.log', '--json'])
            data = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(data['count'], 3)
            self.assertEqual(data['summary']['files_scanned'], 4)
            self.assertEqual(data['summary']['log_lines'], 3)
            self.assertNotIn('person@example.test', out)

    def test_dedup_and_logs_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            logs = root / 'app.log'
            logs.write_text('a@example.test\n')
            (root / 'app.py').write_text('logger.info("%s", user)')
            code, out, _ = self.invoke(['scan', str(root), str(logs), '--mode', 'logs', '--json'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)['count'], 1)

    def test_stdin_and_ansi_unicode_json(self):
        code, out, _ = self.invoke(['scan', '-', '--json'], '\x1b[31mEmail: alice@example.test\x1b[0m\n{"message":"bob\\u0040example.test"}\n')
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)['count'], 2)
        self.assertNotIn('alice@example.test', out)
        self.assertEqual(json.loads(out)['summary']['streams_scanned'], 1)

    def test_json_document_and_python_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'events.json'
            file.write_text(json.dumps([{'message': 'alice@example.test', 'pathname': 'app.py', 'lineno': 42},
                                        {'payload': {'email': 'bob@example.test'}}], indent=2))
            findings = log_scan(file)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]['line'], 42)
            self.assertEqual(findings[1]['json_pointer'], '/1')
            self.assertIsNone(findings[1]['log_line'])

    def test_no_files_binary_bad_encoding_and_long_lines_fail(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.invoke(['scan', d])[0], 2)
            path = Path(d) / 'input.log'
            for data in (b'\x00', b'\xff\xfe', b'x' * (1024 * 1024 + 1)):
                path.write_bytes(data)
                with self.subTest(data_length=len(data)):
                    self.assertEqual(self.invoke(['scan', str(path)])[0], 2)

    def test_config_paths_are_relative_to_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'app.log').write_text('EMP-123456\n')
            (root / 'custom.json').write_text(json.dumps({'version': 1, 'rules': [{'kind': 'EMPLOYEE', 'pattern': 'EMP-[0-9]{6}'}]}))
            config = root / 'logveil.json'
            config.write_text(json.dumps({'version': 1, 'paths': ['app.log'], 'rules': 'custom.json', 'html': 'reports/result.html'}))
            code, out, _ = self.invoke(['scan', '--config', str(config), '--json'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)['findings'][0]['kind'], 'EMPLOYEE')
            self.assertTrue((root / 'reports/result.html').exists())
            # Command-line paths replace configured paths.
            (root / 'clean.log').write_text('ready\n')
            self.assertEqual(self.invoke(['scan', str(root / 'clean.log'), '--config', str(config)])[0], 0)

    def test_generated_outputs_are_not_rescanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'events.log').write_text('person@example.test\n')
            report = root / 'report.txt'
            args = ['scan', str(root), '--html', str(report), '--json']
            first = json.loads(self.invoke(args)[1])
            second = json.loads(self.invoke(args)[1])
            self.assertEqual(first['count'], second['count'])
            self.assertEqual(second['summary']['files_scanned'], 1)

    def test_init_does_not_overwrite_and_config_validation(self):
        with tempfile.TemporaryDirectory() as d:
            previous = Path.cwd()
            try:
                os.chdir(d)
                self.assertEqual(self.invoke(['init'])[0], 0)
                original = Path('logveil.json').read_text()
                self.assertEqual(self.invoke(['init'])[0], 2)
                self.assertEqual(Path('logveil.json').read_text(), original)
                self.assertIn('rules', load_config())
                Path('logveil.json').write_text('{"version":1,"unknown":true}')
                self.assertEqual(self.invoke(['scan'])[0], 2)
            finally:
                os.chdir(previous)

    def test_run_scans_both_streams_without_echoing_raw_payloads(self):
        code, out, err = self.invoke(['run', '--json', '--', sys.executable, '-c',
                                      'import sys; print("alice@example.test"); print("account=1234567890", file=sys.stderr)'])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data['count'], 2)
        self.assertEqual({f['log'] for f in data['findings']}, {'<stdout>', '<stderr>'})
        self.assertNotIn('alice@example.test', out + err)
        self.assertNotIn('1234567890', out + err)

    def test_child_failure_takes_precedence_and_report_shows_it(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / 'report.html'
            code, out, _ = self.invoke(['run', '--json', '--html', str(report), '--', sys.executable, '-c',
                                          'import sys; print("alice@example.test"); sys.exit(7)'])
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(out)['summary']['command_exit_code'], 7)
            self.assertIn('Command failed', report.read_text())

    def test_timeout_missing_executable_and_command(self):
        self.assertEqual(self.invoke(['run', '--timeout', '.1', '--', sys.executable, '-c', 'import time; time.sleep(20)'])[0], 2)
        self.assertEqual(self.invoke(['run', '--', '/nonexistent/logveil-command'])[0], 2)
        self.assertEqual(self.invoke(['run'])[0], 2)

    def test_large_dual_stream_and_no_final_newline(self):
        command = [sys.executable, '-c', 'import sys; [print("ok"*1000) for _ in range(100)]; sys.stderr.write("alice@example.test")']
        findings, stats = scan_command(command)
        self.assertEqual(len(findings), 1)
        self.assertEqual(stats['log_lines'], 101)

    def test_runtime_uses_new_environment_alias(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            path.write_text(json.dumps({'version': 1, 'rules': [{'kind': 'EMPLOYEE', 'pattern': 'EMP-[0-9]{6}'}]}))
            with patch.dict(os.environ, {'LOGVEIL_RULES': str(path)}):
                code, out, _ = self.invoke(['scan', '-'], 'EMP-123456\n')
            self.assertEqual(code, 1)
            self.assertIn('[EMPLOYEE REDACTED]', out)


if __name__ == '__main__':
    unittest.main()
