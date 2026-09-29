import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from pii_guard.guard import install_guard
from pii_guard.workspace import Workspace, result_path


class WorkspaceTests(unittest.TestCase):
    def test_scan_safe_snapshot_export_and_guard_status(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            report, rules = root / 'result.html', root / 'rules.json'
            workspace = Workspace(root, report, rules)
            self.assertTrue(rules.exists())
            self.assertIsNone(workspace.snapshot()['result'])
            log = root / 'service.log'
            log.write_text('alice@example.test\n')
            worker = workspace.start_scan(['service.log'], 'logs')
            worker.join(5)
            snapshot = workspace.snapshot()
            self.assertFalse(snapshot['scan']['running'])
            self.assertIsNone(snapshot['scan']['error'])
            self.assertEqual(len(snapshot['result']['findings']), 1)
            self.assertNotIn('alice@example.test', json.dumps(snapshot))
            self.assertTrue(result_path(report).exists())
            self.assertIsNone(snapshot['guard'])
            logger = logging.Logger('workspace-test')
            logger.addHandler(logging.StreamHandler(io.StringIO()))
            install_guard(rules, status_path=workspace.status_path, logger=logger)
            logger.warning('alice@example.test')
            self.assertEqual(workspace.snapshot()['guard']['protected'], 1)

    def test_root_boundary_and_failed_scan_preserves_previous(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            workspace = Workspace(root, root / 'report.html', root / 'rules.json')
            with self.assertRaises(ValueError):
                workspace.start_scan(['../outside.log'], 'logs')
            (root / 'app.log').write_text('ready\n')
            workspace.start_scan(['app.log'], 'logs').join(5)
            old = workspace.snapshot()['result']
            workspace.start_scan(['missing.log'], 'logs').join(5)
            self.assertIsNotNone(workspace.snapshot()['scan']['error'])
            self.assertEqual(workspace.snapshot()['result'], old)

    def test_one_scan_at_a_time_and_distinct_output_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(ValueError):
                Workspace(root, root / 'rules.json', root / 'rules.json')
            workspace = Workspace(root, root / 'report.html', root / 'rules.json')
            workspace.running = True
            with self.assertRaises(ValueError):
                workspace.start_scan(['.'], 'auto')

    def test_rules_saved_in_ui_reload_in_guard_before_file_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            workspace = Workspace(root, root / 'report.html', root / 'rules.json')
            logger = logging.Logger('file-guard')
            handler = logging.FileHandler(root / 'protected.log', encoding='utf-8')
            logger.addHandler(handler)
            policy = install_guard(workspace.rules, status_path=workspace.status_path, logger=logger)
            from pii_guard.rules_editor import save_rules
            save_rules(workspace.rules, {'version': 1, 'rules': [{'kind': 'STAFF_ID', 'pattern': 'STAFF-[0-9]+'}]})
            try:
                logger.warning('User %s', 'STAFF-876543')
                handler.flush()
                text = (root / 'protected.log').read_text()
                self.assertNotIn('STAFF-876543', text)
                self.assertIn('[STAFF_ID REDACTED]', text)
                self.assertEqual(policy.protected, 1)
            finally:
                handler.close()
