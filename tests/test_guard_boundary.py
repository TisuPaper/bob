import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from pii_guard.guard import GuardPolicy, install_guard, protect_handler, WITHHELD


class GuardBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.Logger('guard-test', logging.DEBUG)
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.logger.addHandler(self.handler)

    def test_mask_before_sink_including_exception_and_no_callsite_changes(self):
        policy = install_guard(logger=self.logger)
        self.logger.info('Customer %s', {'email': 'alice@example.test', 'account': '1234567890'})
        try:
            raise ValueError('alice@example.test')
        except ValueError:
            self.logger.exception('failed')
        output = self.stream.getvalue()
        self.assertNotIn('alice@example.test', output)
        self.assertNotIn('1234567890', output)
        self.assertIn('Traceback', output)
        self.assertEqual(policy.protected, 2)

    def test_json_extra_masking_without_mutating_shared_record(self):
        class Formatter(logging.Formatter):
            def format(self, record):
                return json.dumps({'message': record.getMessage(), 'payload': record.payload})
        self.handler.setFormatter(Formatter())
        policy = install_guard(logger=self.logger)
        record = self.logger.makeRecord('test', logging.INFO, 'service.py', 42, 'Hello', (), None,
                                       extra={'payload': {'email': 'alice@example.test', 'account': 1234567890}})
        self.handler.handle(record)
        self.assertEqual(record.payload['email'], 'alice@example.test')
        parsed = json.loads(self.stream.getvalue())
        self.assertEqual(parsed['payload']['email'], '[EMAIL REDACTED]')
        self.assertIn('****7890', parsed['payload']['account'])
        self.assertEqual(policy.protected, 1)

    def test_live_rules_reload_and_fail_closed_on_invalid_file(self):
        with tempfile.TemporaryDirectory() as d:
            rule = Path(d) / 'rules.json'
            status = Path(d) / 'status.json'
            rule.write_text('{"version":1,"rules":[]}')
            policy = install_guard(rule, status_path=status, logger=self.logger)
            rule.write_text(json.dumps({'version': 1, 'rules': [{'kind': 'STAFF', 'pattern': 'EMP-[0-9]+'}]}))
            self.logger.info('EMP-123456')
            self.assertIn('[STAFF REDACTED]', self.stream.getvalue())
            rule.write_text('{broken')
            self.logger.info('alice@example.test')
            self.assertIn(WITHHELD, self.stream.getvalue())
            telemetry = json.loads(status.read_text())
            self.assertEqual(telemetry['errors'], 1)
            self.assertNotIn('alice', status.read_text())
            rule.write_text('{"version":1,"rules":[]}')
            self.logger.info('alice@example.test')
            self.assertEqual(policy.emissions, 3)

    def test_block_and_formatter_failure_are_closed(self):
        install_guard(mode='block', logger=self.logger)
        self.logger.info('alice@example.test')
        self.assertIn('blocked', self.stream.getvalue())
        self.logger.info('%d', 'not a number')
        self.assertIn(WITHHELD, self.stream.getvalue())

    def test_unsupported_handlers_rejected_and_later_handler_explicit(self):
        self.logger.addHandler(logging.Handler())
        with self.assertRaises(ValueError):
            install_guard(logger=self.logger)
        self.assertIsNone(self.handler.formatter)
        self.logger.removeHandler(self.logger.handlers[-1])
        policy = install_guard(logger=self.logger)
        second = logging.StreamHandler(io.StringIO())
        protect_handler(second, policy)
        self.assertEqual(policy.handlers, 2)

    def test_null_handlers_do_not_prevent_installation(self):
        self.logger.addHandler(logging.NullHandler())
        policy = install_guard(logger=self.logger)
        self.assertEqual(policy.handlers, 1)
        empty = logging.Logger('empty')
        empty.addHandler(logging.NullHandler())
        with self.assertRaises(ValueError):
            install_guard(logger=empty)


if __name__ == '__main__':
    unittest.main()
