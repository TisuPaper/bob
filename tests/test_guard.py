import contextlib
import io
import json
import logging
from pathlib import Path
import runpy
import tempfile
import unittest
from pii_guard.cli import main
from pii_guard.detectors import detect, redact
from pii_guard.fixer import fixed_source, fix
from pii_guard.runtime import JsonFormatter, safe_log
from pii_guard.scanner import log_scan, static_scan


class GuardTests(unittest.TestCase):
    def test_formats_and_redaction(self):
        text = 'email=alice@example.test ic=900101-14-5678 card=4111 1111 1111 1111 account=1234567890'
        self.assertEqual({m.kind for m in detect(text)}, {'EMAIL', 'MY_IC', 'CARD', 'ACCOUNT'})
        masked = redact(text)
        self.assertFalse(detect(masked))
        self.assertNotIn('alice', masked)
        self.assertIn('****1111', masked)
        self.assertFalse(detect('card=4111111111111112 order=12345678'))
        self.assertEqual(detect('account=123456789012')[0].kind, 'ACCOUNT')

    def test_exception_traceback_and_mapping_arguments(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger('test.exception')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        try:
            try:
                raise ValueError('customer=alice@example.test')
            except ValueError:
                safe_log(logger.exception, 'Failed for %(email)s', {'email': 'alice@example.test'})
        finally:
            logger.removeHandler(handler)
        output = stream.getvalue()
        self.assertNotIn('alice@example.test', output)
        self.assertIn('ValueError', output)
        self.assertIn('Traceback', output)
        self.assertEqual(json.loads(output)['source'], __file__)

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            source, logs = Path(d) / 'service.py', Path(d) / 'run.jsonl'
            source.write_text(Path('tests/fixtures/bank_service.py').read_text())
            before_result = runpy.run_path(str(source))['run'](logs)
            before = log_scan(logs)
            self.assertEqual(len(before), 7)
            self.assertEqual(len({f['line'] for f in before}), 3)
            for finding in before:
                self.assertIn('logger.', source.read_text().splitlines()[finding['line'] - 1])
            self.assertEqual(len(static_scan(source)), 3)
            fix(source, apply=True)
            after_result = runpy.run_path(str(source))['run'](logs)
            self.assertEqual(before_result, after_result)
            self.assertEqual(log_scan(logs), [])
            self.assertEqual(static_scan(source), [])
            self.assertEqual(fix(source), [])

    def test_rewrite_unicode_future_imports_and_comments(self):
        source = '''"""doc"""
from __future__ import annotations
label = "你好"; logger.info(
    "Email: %s", # preserve this
    customer.email,
)
'''
        result = fixed_source(source)
        compile(result, '<test>', 'exec')
        self.assertIn('# preserve this', result)
        self.assertIn('from __future__ import annotations', result)
        self.assertEqual(fixed_source(result), result)

    def test_logs_nested_fields_and_unknown_source(self):
        with tempfile.TemporaryDirectory() as d:
            logs = Path(d) / 'logs'
            logs.write_text(json.dumps({'message': 'hello', 'payload': {'account': '1234567890', 'email': 'alice@example.test'}}) + '\nplain alice@example.test\n')
            results = log_scan(logs)
            self.assertEqual(len(results), 3)
            self.assertTrue(all(f['source'] is None for f in results))
            self.assertNotIn('alice', json.dumps(results))

    def test_ci_baseline_and_error_exit(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            logs, baseline = Path(d) / 'logs', Path(d) / 'baseline.json'
            logs.write_text('alice@example.test\n')
            self.assertEqual(main(['scan', '--logs', str(logs), '--write-baseline', str(baseline)]), 1)
            self.assertNotIn('alice', baseline.read_text())
            self.assertEqual(main(['scan', '--logs', str(logs), '--baseline', str(baseline)]), 0)
            with logs.open('a') as stream:
                stream.write('card=4111111111111111\n')
            self.assertEqual(main(['scan', '--logs', str(logs), '--baseline', str(baseline)]), 1)
            self.assertEqual(main(['scan', '--logs', str(logs) + '.missing']), 2)

    def test_json_report_does_not_echo_payload(self):
        with tempfile.TemporaryDirectory() as d:
            logs = Path(d) / 'logs'
            logs.write_text('alice@example.test account=1234567890\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(['scan', '--logs', str(logs), '--json']), 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result['count'], 2)
            self.assertNotIn('alice@example.test', output.getvalue())
            self.assertNotIn('1234567890', output.getvalue())


if __name__ == '__main__':
    unittest.main()
