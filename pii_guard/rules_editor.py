"""Local rules editor and validated atomic persistence."""
import json
from pathlib import Path
import tempfile
from .detectors import parse_rules


def save_rules(path, data):
    parse_rules(data)
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent,
                                         prefix='.rules-', suffix='.json', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.write('\n')
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

