import argparse
import json
import os
import sys
from pathlib import Path
from .config import init_project, load_config
from .detectors import ACTIVE_RULES, get_rules, load_rules, redact
from .fixer import fix
from .inputs import discover
from .runner import scan_command
from .scanner import fingerprint, log_location, log_scan, scan_stream, static_scan
from .web_report import write_html
from .server import serve
from .workspace import result_path, save_result


def safe_data(value):
    """Redact values before serialising so custom regexes cannot break JSON syntax."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [safe_data(item) for item in value]
    if isinstance(value, dict):
        return {key: safe_data(item) for key, item in value.items()}
    return value


def report(findings, as_json=False, summary=None):
    summary = summary or {}
    if as_json:
        print(json.dumps(safe_data({'count': len(findings), 'summary': summary, 'findings': findings}), indent=2))
        return
    print(f'logVeil: {len(findings)} finding(s)')
    if summary:
        print(f"  Scanned {summary.get('files_scanned', 0)} file(s), "
              f"{summary.get('streams_scanned', 0)} stream(s), {summary.get('log_lines', 0)} log line(s). "
              f"Skipped {summary.get('skipped_files', 0)} file(s).")
        if summary.get('command_exit_code') is not None:
            print(f"  Command exit code: {summary['command_exit_code']}")
    for finding in findings:
        location = f"{finding['source']}:{finding['line']}" if finding.get('source') else 'source unknown'
        evidence = f" | log {log_location(finding)}" if finding.get('log') else ''
        print(redact(f"  {finding['kind']:10} {location}{evidence} {finding.get('masked', '')}"))
        print(redact(f"    {finding['path']} ({finding['confidence']})"))


def emit(findings, args, settings, summary):
    baseline = set()
    if args.baseline:
        data = json.loads(Path(args.baseline).read_text(encoding='utf-8'))
        if not isinstance(data, list) or any(not isinstance(value, str) for value in data):
            raise ValueError('Baseline must be a JSON list of fingerprints')
        baseline = set(data)
    if args.write_baseline:
        Path(args.write_baseline).write_text(json.dumps(sorted({fingerprint(f) for f in findings}), indent=2) + '\n', encoding='utf-8')
    visible = [f for f in findings if fingerprint(f) not in baseline]
    summary['suppressed'] = len(findings) - len(visible)
    html = args.html or settings.get('html')
    if html:
        Path(html).parent.mkdir(parents=True, exist_ok=True)
        write_html(html, visible, suppressed=summary['suppressed'], summary=summary)
        save_result(html, visible, summary)
    report(visible, args.json, summary)
    if html:
        print(f'Open report: {Path(html).resolve().as_uri()}', file=sys.stderr if args.json else sys.stdout)
    if summary.get('command_exit_code', 0) != 0:
        return 3
    return 1 if visible else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='logveil', description='Local sensitive-data scanner for logs, command output and Python logging calls.')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init', help='Create project settings and an empty custom rule file')
    scan = commands.add_parser('scan', help='Scan files/directories or stdin (-)')
    scan.add_argument('paths', nargs='*', help='Auto: Python source or text/log files; directories are recursive')
    scan.add_argument('--logs', action='append', default=[], help='Additional log file/directory (repeatable)')
    scan.add_argument('--mode', choices=['auto', 'logs', 'python'], help='Interpret positional inputs; default auto')
    scan.add_argument('--exclude', action='append', default=[], help='Exclude glob relative to each input root (repeatable)')
    run = commands.add_parser('run', help='Execute a command and inspect stdout/stderr (no shell)')
    run.add_argument('--timeout', type=float, default=300, help='Maximum command duration in seconds (default 300)')
    run.add_argument('program', nargs=argparse.REMAINDER, help='-- executable arguments')
    repair = commands.add_parser('fix', help='Preview Python logging repairs; --apply writes changes')
    repair.add_argument('source')
    repair.add_argument('--apply', action='store_true')
    serve_parser = commands.add_parser('serve', help='Host a report and custom-rules editor on localhost')
    serve_parser.add_argument('report', nargs='?')
    serve_parser.add_argument('--port', type=int, default=8000)
    serve_parser.add_argument('--root', help='Workspace root allowed for browser scans (default config directory or cwd)')
    serve_parser.add_argument('--status', help='Guard status file (default ROOT/.logveil/guard-status.json)')
    for command in (scan, run, repair, serve_parser):
        command.add_argument('--config', help='Project JSON settings (default ./logveil.json if present)')
        command.add_argument('--rules', help='Custom rules JSON; overrides environment and project settings')
    for command in (scan, run):
        command.add_argument('--json', action='store_true')
        command.add_argument('--html', metavar='PATH')
        command.add_argument('--baseline')
        command.add_argument('--write-baseline')
    args = parser.parse_args(argv)
    token = None
    try:
        if args.command == 'init':
            init_project()
            print('Created logveil.json and logveil-rules.json. Edit paths, then run logveil scan.')
            return 0
        settings = load_config(args.config)
        rule_path = args.rules or os.environ.get('LOGVEIL_RULES') or os.environ.get('PII_GUARD_RULES') or settings.get('rules')
        if args.command == 'serve':
            html = args.report or settings.get('html') or 'scan-results.html'
            root = args.root or (str(Path(settings['_file']).parent) if settings.get('_file') else str(Path.cwd()))
            return serve(html, args.port, rule_path or str(Path(root) / 'logveil-rules.json'), root, args.status)
        token = ACTIVE_RULES.set(load_rules(rule_path) if rule_path else get_rules())
        if args.command == 'fix':
            changes = fix(args.source, args.apply)
            for _, diff in changes:
                print(redact(diff))
            print(f"{len(changes)} file(s) {'updated' if args.apply else 'would change (use --apply)'}")
            if rule_path:
                print('For custom masking, set LOGVEIL_RULES to the same rules file when launching your application.')
            return 0
        if args.command == 'run':
            program = args.program[1:] if args.program[:1] == ['--'] else args.program
            print('logVeil is capturing stdout/stderr; raw output is not echoed or saved.', file=sys.stderr)
            findings, summary = scan_command(program, args.timeout)
        else:
            mode = args.mode or settings.get('mode', 'auto')
            paths = args.paths or ([] if args.logs else settings.get('paths', []))
            if not paths and not args.logs:
                raise ValueError('Provide a path, --logs, stdin (-), or run logveil init to configure paths')
            requests = [(path, mode) for path in paths] + [(path, 'logs') for path in args.logs]
            stdin_count = sum(path == '-' for path, _ in requests)
            if stdin_count > 1 or (stdin_count and mode == 'python'):
                raise ValueError('stdin (-) is supported once, in auto/logs mode')
            html = args.html or settings.get('html')
            ignored = [html, result_path(html) if html else None, rule_path, settings.get('_file'), args.baseline, args.write_baseline]
            files, skipped = discover([(p, m) for p, m in requests if p != '-'],
                                      settings.get('exclude', []) + args.exclude, ignored) if len(requests) > stdin_count else ([], 0)
            summary = {'files_scanned': len(files), 'streams_scanned': stdin_count, 'log_lines': 0, 'skipped_files': skipped}
            findings = []
            for file, file_mode in files:
                findings.extend(static_scan(file) if file_mode == 'python' else log_scan(file, summary))
            if stdin_count:
                findings.extend(scan_stream(sys.stdin, '<stdin>', summary))
        return emit(findings, args, settings, summary)
    except KeyboardInterrupt:
        print('logVeil: interrupted; scan incomplete.', file=sys.stderr)
        return 130
    except (OSError, SyntaxError, ValueError, EOFError, RecursionError) as exc:
        # Source text, paths, child command arguments and raw payloads never enter diagnostics.
        detail = str(exc) if type(exc) is ValueError else 'Check paths, permissions, UTF-8 input, Python syntax and JSON configuration.'
        print(f'logVeil: {type(exc).__name__}: {redact(detail)} No fresh report was completed.', file=sys.stderr)
        return 2
    finally:
        if token is not None:
            ACTIVE_RULES.reset(token)
