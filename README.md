# PII Log Guard

A dependency-free Python CLI for the **PII Log Leak Detector** use case. It scans Python logging calls and captured logs, reports masked evidence with source locations, previews/applies masking repairs, and verifies a fresh run.

Requires Python 3.10+. Run commands from this checkout; no installation or API key is required.

## One-command demo

```sh
python3 -m pii_guard demo
```

The demo copies a synthetic bank service into a temporary directory, executes it, scans the logs, applies repairs to the copy, executes it again, and compares the service results. Your example source stays available for another demonstration. Temporary logs are removed on exit.

Expected result:

```text
Leaking statements: 3 → 0
Detected PII values: 7 → 0
Service results unchanged: True
```

The three planted paths are:

| Scenario | Flow | Observed data |
| --- | --- | --- |
| Direct field | Customer.email → logger.info → log | Email |
| Whole object | Customer → dataclass representation → logger.info → log | Email, Malaysian IC, card, account |
| Exception text | Customer fields → ValueError → logger.error → log | Email, account |

Reports distinguish **static heuristic risks** from **observed runtime patterns**. Multiple PII values can originate from one logging statement.

## Scan, fix, verify

```sh
# Static scan (exit 1 is expected while risks exist)
python3 -m pii_guard scan examples/bank_service.py

# Capture an example run and trace observed leaks to source locations
mkdir -p .demo
PYTHONPATH=. python3 examples/bank_service.py .demo/before.jsonl
python3 -m pii_guard scan --logs .demo/before.jsonl
python3 -m pii_guard scan examples/bank_service.py --logs .demo/before.jsonl --json

# Preview a masked diff; applying modifies this file, so use a copy for repeat demos
cp examples/bank_service.py .demo/bank_service.py
python3 -m pii_guard fix .demo/bank_service.py
python3 -m pii_guard fix .demo/bank_service.py --apply
PYTHONPATH=. python3 .demo/bank_service.py .demo/after.jsonl
python3 -m pii_guard scan .demo/bank_service.py --logs .demo/after.jsonl
```

Repairs wrap supported logging calls with `pii_guard.runtime.safe_log`. The wrapper formats interpolated fields, objects and exceptions, masks recognized values, then emits the message. It preserves logging source locations through `stacklevel`. The generated call uses an inline import to avoid changing future imports, docstrings, or existing bindings. Keep `pii_guard` importable in the repaired application's environment. For a maintained application, you can replace the generated inline import with a normal `from pii_guard.runtime import safe_log` import.

`fix` previews by default and applies only with `--apply`. Diffs are redacted for display and therefore are **not patch files**. It wraps all supported calls in the selected files, including constant messages, and is idempotent.

## Trace actual test-run logs

Attach the included formatter to a Python logging handler used by your tests:

```python
import logging
from pii_guard.runtime import JsonFormatter

handler = logging.FileHandler("test-run.jsonl", mode="w", encoding="utf-8")
handler.setFormatter(JsonFormatter())
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)
```

Then run your tests and scan `test-run.jsonl`. Each JSON line contains `source`, `line`, `level`, and `message`; traceback text stays within the record. The scanner also accepts plain text logs, but reports **source unknown** when source metadata is absent. Structured nested fields are scanned too. Source locations are taken from log metadata, not independently authenticated. Use logs from the matching code revision.

The path explanation is an observed logging-call-to-log link. It is not a whole-program data-flow proof, and arbitrary plain logs cannot reliably be traced back to code.

## CI: block newly observed findings

```sh
# Deliberately record accepted findings; still exits 1 if findings exist
python3 -m pii_guard scan examples --logs test-run.jsonl --write-baseline baseline.json

# Subsequent CI runs only fail on findings absent from the baseline
python3 -m pii_guard scan examples --logs test-run.jsonl --baseline baseline.json --json
```

Exit codes: **0** no unbaselined findings, **1** findings, **2** invalid/unreadable input. Baselines contain location/type fingerprints, never payloads or payload-derived hashes. Fingerprints depend on path, line, origin and type: use stable paths in CI. Moving a line is a new finding; another value of the same type at an accepted location is suppressed. Review accepted locations accordingly.

## Detection scope

- Email format candidates; email evidence is fully removed from reports.
- Malaysian IC formats: 12 digits or `######-##-####` (format only, not identity/date validation).
- Card candidates: 13–19 digits with optional spaces/hyphens, checked with Luhn.
- Account numbers: 8–18 digits following `account`, `account_number`, `account_no`, or `acct` with `:`/`=` context.
- Numeric evidence retains only its final four digits.

Static scanning uses Python AST and recognizes `logger`, `logging`, and `log` calls with standard named severity methods. It does not resolve aliases, custom loggers, `print`, `logger.log`, or interprocedural flows. Dynamic values can be harmless, so static findings require review. The fixer supports the same calls. Masking covers message text, formatted exception text and requested stack text; custom structured `extra` fields require separate field-level masking. The runtime scanner can flag these fields if they are included in your captured JSON records.

These patterns are a bounded demo, not proof that a program is free of sensitive data: names, addresses, other national IDs, encodings and unlabelled account numbers may be missed. A clean rerun means the exercised logs contain no matches for the configured detectors. Original captured logs still contain their original data; only reports and repaired future messages are masked.

## IBM Bob demo workflow

Open this project in IBM Bob, run the demo in its terminal, inspect the reported example lines, and review the generated masking diff. Apply repairs, run the service/tests again, and show the clean report. This repository provides a deterministic repair engine and does not call or require an IBM Bob API.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover detector boundaries, masked output, source tracing, object/exception leaks, traceback redaction, logging mapping arguments, Unicode source edits, idempotent repairs, nested log fields, baseline gating, and before/after service behavior.
