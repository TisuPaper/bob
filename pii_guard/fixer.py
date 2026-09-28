"""Explicit, reviewable rewrites of supported Python logging calls."""
import ast
import difflib
from pathlib import Path
from .scanner import logging_calls, python_files


def fixed_source(source):
    tree = ast.parse(source)
    nodes = list(logging_calls(tree))
    if not nodes:
        return source
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def position(line, column):
        # AST columns are UTF-8 byte offsets, not Unicode character offsets.
        return offsets[line - 1] + len(lines[line - 1].encode("utf-8")[:column].decode("utf-8"))

    edits = []
    # Insert only a prefix and a suffix, preserving original argument syntax/comments.
    for node in nodes:
        start = position(node.lineno, node.col_offset)
        func_end = position(node.func.end_lineno, node.func.end_col_offset)
        end = position(node.end_lineno, node.end_col_offset)
        opening = source.index("(", func_end, end)
        edits.extend([(start, start, '__import__("pii_guard.runtime", fromlist=["safe_log"]).safe_log('),
                      (opening, opening + 1, ", ")])
    for start, end, replacement in sorted(edits, reverse=True):
        source = source[:start] + replacement + source[end:]
    ast.parse(source)
    return source


def fix(path, apply=False):
    changes = []
    for file in python_files(path):
        original = file.read_text(encoding="utf-8")
        revised = fixed_source(original)
        if original != revised:
            changes.append((str(file), "".join(difflib.unified_diff(
                original.splitlines(True), revised.splitlines(True),
                fromfile=str(file), tofile=str(file) + " (masked)"))))
            if apply:
                file.write_text(revised, encoding="utf-8")
    return changes
