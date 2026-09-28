import contextlib
from html.parser import HTMLParser
import io
from pathlib import Path
import tempfile
import unittest
from pii_guard.cli import main
from pii_guard.web_report import write_html


class WebReportTests(unittest.TestCase):
    def test_escapes_untrusted_fields_and_redacts_values(self):
        finding = {'origin': 'runtime', 'kind': 'EMAIL', 'source': '<script>alert(1)</script>',
                   'line': 5, 'masked': 'alice@example.test', 'log': 'run.log', 'log_line': 1,
                   'path': '<img src=x onerror=alert(1)>', 'confidence': 'observed-pattern',
                   'suggestion': 'Mask alice@example.test'}
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'report.html'
            write_html(output, [finding])
            page = output.read_text()
            self.assertNotIn('alice@example.test', page)
            self.assertNotIn('<script>alert(1)', page)
            self.assertNotIn('<img src=x', page)
            self.assertIn('&lt;script&gt;', page)
            self.assertIn('[EMAIL REDACTED]', page)
            HTMLParser().feed(page)

    def test_scan_html_retains_exit_code_and_baseline_counts(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            logs, output, baseline = [Path(d) / p for p in ['run.log', 'report.html', 'baseline.json']]
            logs.write_text('Email: alice@example.test\n')
            self.assertEqual(main(['scan', '--logs', str(logs), '--html', str(output), '--write-baseline', str(baseline)]), 1)
            self.assertIn('Email address', output.read_text())
            self.assertNotIn('alice@example.test', output.read_text())
            self.assertEqual(main(['scan', '--logs', str(logs), '--html', str(output), '--baseline', str(baseline)]), 0)
            self.assertIn('1 finding(s) excluded by baseline', output.read_text())
            self.assertIn('No detected findings', output.read_text())

    def test_demo_comparison(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            output = Path(d) / 'demo.html'
            self.assertEqual(main(['demo', '--html', str(output)]), 0)
            page = output.read_text()
            self.assertIn('7 before', page)
            self.assertIn('0 after', page)
            self.assertIn('Rerun clean', page)
            self.assertNotIn('demo.customer@example.test', page)
            self.assertNotIn('4111111111111111', page)


if __name__ == '__main__':
    unittest.main()
