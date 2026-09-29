# logVeil technical reference

[Back to README](../README.md)

## Input discovery

`logveil scan PATH...` accepts files and directories. `--logs PATH` adds log inputs; `-` reads stdin once. Modes:

| Mode | Explicit files | Discovered directory files |
| --- | --- | --- |
| `auto` | `.py` as Python; others as logs | Supported Python/log extensions |
| `logs` | Any extension as logs | Log/text extensions, excluding Python |
| `python` | `.py` only | `.py` only |

Log extensions: `.log`, `.log.NUMBER`, `.jsonl`, `.ndjson`, `.json`, `.txt`, `.out`, `.err`, optionally ending in `.gz`. Use explicit paths for other names. Inputs must be UTF-8 (a leading BOM is accepted); invalid encodings and NUL bytes fail. Windows/Linux/macOS log text can be inspected regardless of the generating language. ANSI colour sequences are stripped before matching.

Directory traversal skips `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.demo`, `.logveil`, `build`, `dist`, `.tox`, `.mypy_cache`, `.pytest_cache`, and symlinks. Explicit symlink inputs are rejected; use the real path. Repeated files of the same mode are deduplicated. Directory traversal failures stop the scan. `.gitignore` is not interpreted.

`--exclude GLOB` matches filenames or paths relative to each input root. Repeat the flag for more exclusions. Selected output, baseline, rule and project configuration files are excluded automatically. The skipped count counts encountered excluded/unsupported files; contents of pruned directories are not enumerated.

Log streams are processed line by line with a **1 MiB line limit**. JSON documents (`.json`, `.json.gz`) are decoded as a whole with a **16 MiB document limit**; larger sources should use JSONL. A JSON array is scanned per top-level element, with its JSON pointer shown instead of an invented physical line number. Findings are retained in memory until reporting, so memory use grows with the number of findings.

These limits fail with exit code 2. On incomplete scans no new report is written; an older report at that path may still exist. Do not treat it as the current scan's result.

## Configuration

`logveil init` creates:

- `logveil.json`: default paths, mode, exclusions, rules and report path.
- `logveil-rules.json`: an empty custom rule list; built-ins stay enabled.

The CLI reads `logveil.json` only in the current working directory, not parent directories. `--config PATH` explicitly selects another file. Relative paths inside it resolve against the config directory. Command-line paths resolve against the working directory. `--logs` without positional inputs replaces configured input paths too.

Rule precedence: **`--rules` → `LOGVEIL_RULES` → `PII_GUARD_RULES` → project rules → built-ins**. `serve --rules` selects the file the browser may edit; it does not change prior report results. When no rule path is configured, the workspace creates an empty `logveil-rules.json` if needed.

## Source tracing

Plain logs have a log path and physical line number. Structured records can supply either:

```json
{"source": "src/service.py", "line": 42, "message": "..."}
```

or:

```json
{"pathname": "src/service.py", "lineno": 42, "message": "..."}
```

The same shape works for other languages. Nested fields are scanned for sensitive patterns, but other source metadata schemas are not interpreted. Metadata is reported as supplied, not authenticated; use logs from the matching code revision. This is not whole-program data-flow analysis.

Python applications can capture that metadata with:

```python
import logging
from pii_guard.runtime import JsonFormatter

handler = logging.FileHandler("test-run.jsonl", mode="w", encoding="utf-8")
handler.setFormatter(JsonFormatter())
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)
```

## Command capture

`logveil run [OPTIONS] -- executable args...` runs a real program and concurrently scans stdout and stderr, including the final line without a newline. Command arguments and raw payloads are not copied into reports. Original application output is not echoed or saved; only findings and execution status are returned.

Use `--timeout SECONDS` for a finite positive deadline (default 300). Timeout, invalid output encoding, oversized lines, launch failure or interruption cannot return a clean status. On POSIX, interrupted/failed capture stops the child process group; on Windows it stops the direct child. Interactive programs, terminal output semantics and cross-line patterns are not supported. Application-created log files must be scanned separately. It is not a proxy or sandbox: programs retain their normal filesystem/network access and side effects.

CI should use the logVeil exit code, not just the finding count. Exit 3 means the program failed, even if a baseline suppressed all findings. `summary.command_exit_code` preserves the child's return code.

## Custom rule fields

Edit the selected JSON file directly or use `/rules` on the local server. The editor validates before saving, writes atomically, and rejects stale browser revisions. Regex validity does not guarantee that a rule has the intended coverage; test matching, nonmatching, overlapping and already-redacted examples.

```json
{
  "version": 1,
  "rules": [
    {
      "kind": "API_TOKEN",
      "pattern": "(?i)\\bapi_token\\s*[:=]\\s*(?P<secret>[A-Za-z0-9_-]{16,})",
      "group": "secret"
    }
  ]
}
```

| Field | Meaning | Default |
| --- | --- | --- |
| `kind` | Unique uppercase name; cannot replace a built-in | Required |
| `pattern` | Python regex; backslashes are escaped in JSON | Required |
| `group` | Named capture containing the sensitive part | Entire match |
| `keep_last` | Retain 0–4 trailing characters; fully redact values no longer than this | `0` |
| `priority` | Higher priority wins overlaps | `200` |
| `validator` | Optional `"luhn"` numeric checksum | None |

Built-in account rules have priority 200; other built-ins have 100. Built-ins register first; equal priorities preserve registration order. Lower-priority overlapping matches are skipped. Use contextual patterns that do not match redaction markers. Unknown fields, duplicate kinds, invalid regexes/groups and unsupported validators are rejected.

`rules/custom.json` in the source repository is an optional set of sample rules; installation does not depend on that file. The `safe_log` helper caches environment rules per process. The handler guard reloads a changed rule file at the next event.

## Pre-emission guard

`pii_guard.guard.install_guard(rules_path, status_path=..., mode="mask")` wraps the formatters on existing standard text handlers, including root/named loggers and the last-resort handler. Pass `logger=...` to protect only its direct handlers. Logging configuration must be complete before installation. Non-emitting NullHandlers are ignored. A handler added later needs `protect_handler(handler, policy)`.

The guard clones the LogRecord, renders interpolation, sanitizes fields and exception/stack text, invokes the original formatter, and masks any remaining matches in its final text. The original record is not modified. This covers built-in StreamHandler/FileHandler emission behavior; custom subclasses that bypass format() are outside the contract. QueueHandler, SocketHandler, HTTPHandler and other non-text handlers are rejected at installation. Formatters must not perform their own logging/output side effects.

In `mask` mode only detected spans are replaced. In `block` mode the full formatted message is replaced by a fixed marker when a pattern matches. Formatting failures and unreadable/invalid updated rules emit a protection-error marker rather than the original message. Rule regex execution has no timeout; trusted, tested rules are still required. Rules can miss sensitive formats, so no complete confidentiality guarantee is implied.

The rule file is checked at every handler emission using its modification time, size and inode. Writes from the editor are atomic. Failed updates do not silently use a stale policy: affected emissions are withheld until a valid file is restored. Keep the server editor and the application pointed at the same rules file.

`status_path` is optional. It records process ID, timestamps, mode, handler count, inspected emissions, protected emissions and protection errors. One process should own a given status file. Each handler is an emission: one log event going to two handlers counts twice. The UI distinguishes recent events from stale observations and does not infer whether an application is currently running. Status write errors do not allow raw logs through. The status file is updated per event; leave it disabled if that disk overhead is undesirable.

## Workspace API and scope

The loopback server provides a three-page UI: scans, protection and rules. Mutating requests require a random session token, matching Host and same-origin browser requests. Browser scans accept only paths resolving inside `--root`; no shell commands or code repairs can be triggered from the frontend. One browser scan runs at a time, with progress/status polled by the page. Pattern matching still executes trusted regexes in the server process.

The CLI writes a masked report companion alongside HTML. The workspace reads it to load current findings and preserve results across restarts. Browser scans use saved rules and explicit scan inputs; project CLI exclusions and baselines are not currently applied by browser scans. Use the CLI when those policies are required. Failed scans retain previous results and display a failure state.

## Python scanning and repairs

AST scanning recognises named severity methods on `logger`, `logging` and `log`. Dynamic interpolation, logged objects, literal sensitive values and exception logging can produce heuristic findings. It does not resolve aliases, logging wrappers, `print`, `logger.log`, or arbitrary interprocedural flows.

`logveil fix PATH` previews changes and `--apply` writes them. The fixer wraps all supported calls, including constant ones, and is idempotent. Displayed diffs are masked and are not patch files. Generated inline imports preserve existing imports/docstrings. The helper formats arguments, objects and exception text, redacts matches, and preserves source location through logging `stacklevel`. Structured `extra` fields require separate masking.

A repaired application's environment needs the installed `pii_guard` package. Set `LOGVEIL_RULES` in that application to enable custom runtime rules; selecting CLI rules for the fix does not embed them in generated code.

## Built-in coverage

- Emails: format candidates, fully masked.
- Malaysian IC: 12 digits or `######-##-####`, without date or identity validation.
- Payment cards: 13–19 digit candidates with optional separators and Luhn checksum.
- Accounts: 8–18 digits after `account`, `account_number`, `account_no`, or `acct` with `:`/`=` context.
- Numeric matches retain their last four characters.

Names, addresses, other national identifiers, encoded data and unlabelled accounts may require custom rules or additional detectors. A successful scan verifies only the provided inputs against configured patterns. It does not establish compliance or complete confidentiality.

## CI baselines

```sh
# Explicitly record reviewed existing findings (exit 1 still means findings exist)
logveil scan ./logs --write-baseline baseline.json

# Only unbaselined findings cause exit 1
logveil scan ./logs --baseline baseline.json --html scan-results.html --json
```

Baselines store location/origin/type fingerprints, not payloads or payload-derived hashes. Stable input paths are needed: moving a line creates a new fingerprint; another value of the same type at an accepted location is suppressed. Command streams use `<stdout>` and `<stderr>` line numbers; keep separate baselines for distinct commands. JSON documents without source metadata use their top-level element pointer.

Reports are masked but source paths may still be useful internal information. Raw input logs remain unchanged. With `--json`, the report link goes to stderr so stdout remains parseable JSON.
