#!/usr/bin/env python3
"""Build a portable logVeil executable using only Python's standard library."""
import argparse
from pathlib import Path
import shutil
import tempfile
import zipapp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='dist/logveil', help='Archive path (default dist/logveil)')
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='logveil-build-') as directory:
        staging = Path(directory)
        shutil.copytree(project / 'pii_guard', staging / 'pii_guard',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (staging / '__main__.py').write_text('from pii_guard.cli import main\nraise SystemExit(main())\n', encoding='utf-8')
        zipapp.create_archive(staging, output, interpreter='/usr/bin/env python3', compressed=True)
        output.chmod(0o755)
    print(f'Built {output}\nRun: {output} --help')


if __name__ == '__main__':
    main()
