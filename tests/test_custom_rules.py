import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from pii_guard.cli import main
from pii_guard.detectors import ACTIVE_RULES, detect, load_rules, redact
from pii_guard.fixer import fixed_source


class CustomRuleTests(unittest.TestCase):
    def test_additive_rules_capture_masking_and_scope(self):
        token = ACTIVE_RULES.set(load_rules('rules/custom.json'))
        try:
            text = 'EMP-123456 PAT-12345678 api_token=abcdefghijklmnop alice@example.test'
            self.assertEqual({m.kind for m in detect(text)}, {'EMPLOYEE_ID', 'PATIENT_ID', 'API_TOKEN', 'EMAIL'})
            masked = redact(text)
            self.assertIn('api_token=[API_TOKEN REDACTED]', masked)
            self.assertIn('[PATIENT_ID ****5678]', masked)
            self.assertNotIn('EMP-123456', masked)
            self.assertEqual(detect(masked), [])
        finally:
            ACTIVE_RULES.reset(token)
        self.assertEqual(detect('EMP-123456'), [])

    def test_cli_static_runtime_html_baseline(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            source, logs, html, baseline = [Path(d) / name for name in ('app.py', 'run.log', 'report.html', 'baseline.json')]
            source.write_text('logger.info("EMP-123456")\n')
            logs.write_text('EMP-123456\n')
            arguments = ['scan', str(source), '--logs', str(logs), '--rules', 'rules/custom.json', '--html', str(html)]
            self.assertEqual(main(arguments + ['--write-baseline', str(baseline)]), 1)
            page = html.read_text()
            self.assertIn('EMPLOYEE_ID', page)
            self.assertNotIn('EMP-123456', page)
            self.assertNotIn('EMP-123456', baseline.read_text())
            self.assertEqual(main(arguments + ['--baseline', str(baseline)]), 0)
            self.assertEqual(detect('EMP-123456'), [])

    def test_fixed_application_loads_environment_rules(self):
        source = 'import logging\nlogging.basicConfig(level=logging.INFO)\nlogger = logging.getLogger("test")\nlogger.info("Employee %s", "EMP-123456")\n'
        env = dict(os.environ, PII_GUARD_RULES=str(Path('rules/custom.json').resolve()))
        result = subprocess.run([sys.executable, '-c', fixed_source(source)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[EMPLOYEE_ID REDACTED]', result.stderr)
        self.assertNotIn('EMP-123456', result.stderr)

    def test_invalid_rules_fail_before_outputs(self):
        invalid = [
            {'kind': 'EMAIL', 'pattern': 'x'},
            {'kind': 'NEW', 'pattern': '('},
            {'kind': 'NEW', 'pattern': 'x', 'group': 'missing'},
            {'kind': 'NEW', 'pattern': 'x', 'keep_last': 9},
            {'kind': 'NEW', 'pattern': 'x*'},
            {'kind': 'NEW', 'pattern': 'x', 'validator': 'unknown'},
            {'kind': 'NEW', 'pattern': 'x', 'typo': True},
        ]
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / 'rules.json'
            for rule in invalid:
                with self.subTest(rule=rule):
                    config.write_text(json.dumps({'version': 1, 'rules': [rule]}))
                    with self.assertRaises(ValueError):
                        load_rules(config)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(['scan', 'examples', '--rules', str(config)]), 2)
            self.assertNotIn('"pattern"', stderr.getvalue())

    def test_priority_and_short_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            path.write_text(json.dumps({'version': 1, 'rules': [
                {'kind': 'FIRST', 'pattern': 'EMP-[0-9]+', 'priority': 300},
                {'kind': 'SECOND', 'pattern': 'EMP-[0-9]+', 'priority': 200},
                {'kind': 'SHORT', 'pattern': '\\bXYZ\\b', 'keep_last': 4}]}))
            token = ACTIVE_RULES.set(load_rules(path))
            try:
                self.assertEqual(detect('EMP-123456')[0].kind, 'FIRST')
                self.assertEqual(redact('XYZ'), '[SHORT REDACTED]')
            finally:
                ACTIVE_RULES.reset(token)


if __name__ == '__main__':
    unittest.main()
