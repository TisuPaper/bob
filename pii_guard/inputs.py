"""Discover local inputs without following directory symlinks or scanning outputs."""
import fnmatch
import os
from pathlib import Path
import re
from .scanner import SKIP

SKIP_DIRS = SKIP | {'.logveil', 'build', 'dist', '.tox', '.mypy_cache', '.pytest_cache'}
LOG_NAME = re.compile(r'\.(?:log(?:\.\d+)?|jsonl|ndjson|json|txt|out|err)(?:\.gz)?$', re.I)


def discover(requests, excludes=(), ignored=()):
    """requests: (path, auto/logs/python). Returns files plus skipped file count."""
    selected, seen, skipped = [], set(), 0
    ignored = {Path(p).resolve() for p in ignored if p}

    def excluded(file, root):
        relative = file.relative_to(root).as_posix()
        return any(fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(file.name, pattern)
                   for pattern in excludes)

    def add(file, mode, root, explicit=False):
        nonlocal skipped
        if file.is_symlink() or file.resolve() in ignored or excluded(file, root):
            skipped += 1
            return
        file_mode = 'python' if mode == 'python' or (mode == 'auto' and file.suffix == '.py') else 'logs'
        supported = file.suffix == '.py' if file_mode == 'python' else bool(LOG_NAME.search(file.name))
        if not supported and not (explicit and mode != 'python'):
            skipped += 1
            return
        key = (file.resolve(), file_mode)
        if key not in seen:
            seen.add(key)
            selected.append((file, file_mode))

    def walk_error(error):
        raise error

    for value, mode in requests:
        path = Path(value)
        if path.is_symlink():
            raise ValueError('Explicit input symlinks are not supported; use the real path')
        if path.is_file():
            add(path, mode, path.parent, explicit=True)
        elif path.is_dir():
            for current, directories, files in os.walk(path, onerror=walk_error, followlinks=False):
                root = Path(current)
                directories[:] = sorted(d for d in directories if d not in SKIP_DIRS
                                        and not (root / d).is_symlink() and not excluded(root / d, path))
                for name in sorted(files):
                    add(root / name, mode, path)
        else:
            raise ValueError('Input does not exist or is not a regular file/directory')
    if not selected:
        raise ValueError('No supported input files found; check paths, mode and exclusions')
    return selected, skipped
