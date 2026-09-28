import argparse
import json
import runpy
import shutil
import sys
import tempfile
from pathlib import Path
from .detectors import redact
from .fixer import fix
from .scanner import fingerprint, log_scan, static_scan


def report(findings, as_json=False):
    # Final redaction also protects sensitive strings in file names.
    if as_json:
        print(redact(json.dumps({"count": len(findings), "findings": findings}, indent=2)))
        return
    print(f"PII Log Guard: {len(findings)} finding(s)")
    for f in findings:
        location = f"{f['source']}:{f['line']}" if f.get("source") else "source unknown"
        evidence = f" | log {f['log']}:{f['log_line']}" if f.get("log") else ""
        print(redact(f"  {f['kind']:10} {location}{evidence} {f.get('masked', '')}"))
        print(f"    {f['path']} ({f['confidence']})")


def demo():
    template = Path(__file__).resolve().parent.parent / "examples" / "bank_service.py"
    if not template.exists():
        raise ValueError("Run demo from the source checkout (example service required).")
    with tempfile.TemporaryDirectory(prefix="pii-demo-") as directory:
        root = Path(directory)
        service, logs = root / "bank_service.py", root / "test-run.jsonl"
        shutil.copyfile(template, service)
        before_result = runpy.run_path(str(service))["run"](logs)
        before = log_scan(logs)
        print("BEFORE — three planted logging leaks")
        report(before)
        changes = fix(service, apply=True)
        print(f"\nApplied masking to {len(changes)} file(s) in a temporary copy.")
        after_result = runpy.run_path(str(service))["run"](logs)
        after = log_scan(logs)
        print("AFTER — fresh execution and fresh logs")
        report(after)
        before_sites = len({(f['source'], f['line']) for f in before})
        after_sites = len({(f['source'], f['line']) for f in after})
        print(f"Leaking statements: {before_sites} → {after_sites}")
        print(f"Detected PII values: {len(before)} → {len(after)}")
        unchanged = before_result == after_result
        print(f"Service results unchanged: {unchanged}")
        return 0 if before_sites == 3 and not after and unchanged else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan Python logging risks and actual logs for PII.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Exit 1 on findings; 2 on input errors")
    scan.add_argument("source", nargs="?", help="Python file or directory (static heuristics)")
    scan.add_argument("--logs", action="append", default=[], help="Text or JSONL log; repeatable")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--baseline", help="Only report fingerprints absent from this baseline")
    scan.add_argument("--write-baseline", help="Write a baseline of all current findings")
    repair = commands.add_parser("fix", help="Preview masking changes; use --apply to write")
    repair.add_argument("source")
    repair.add_argument("--apply", action="store_true")
    commands.add_parser("demo", help="Run scan → fix → rerun in a temporary copy")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            return demo()
        if args.command == "fix":
            changes = fix(args.source, args.apply)
            for _, diff in changes:
                print(redact(diff))
            print(f"{len(changes)} file(s) {'updated' if args.apply else 'would change (use --apply)'}")
            return 0
        if not args.source and not args.logs:
            parser.error("scan requires a source path or --logs")
        findings = static_scan(args.source) if args.source else []
        for log in args.logs:
            findings.extend(log_scan(log))
        baseline = set()
        if args.baseline:
            data = json.loads(Path(args.baseline).read_text())
            if not isinstance(data, list) or any(not isinstance(x, str) for x in data):
                raise ValueError("Baseline must be a JSON list of fingerprints")
            baseline = set(data)
        if args.write_baseline:
            Path(args.write_baseline).write_text(json.dumps(sorted({fingerprint(f) for f in findings}), indent=2) + "\n")
        visible = [f for f in findings if fingerprint(f) not in baseline]
        report(visible, args.json)
        return 1 if visible else 0
    except (OSError, SyntaxError, ValueError) as exc:
        # Do not echo exception details, which can contain source text or PII.
        print(f"pii-guard: {type(exc).__name__}: input could not be processed; check paths, Python syntax, and JSON.", file=sys.stderr)
        return 2
