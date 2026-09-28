"""Portable per-project settings. Relative settings resolve beside the config file."""
import json
from pathlib import Path

DEFAULT = {
    'version': 1,
    'paths': ['.'],
    'mode': 'auto',
    'exclude': ['tests/*'],
    'rules': 'logveil-rules.json',
    'html': '.logveil/report.html',
}


def load_config(path=None):
    file = Path(path) if path else Path.cwd() / 'logveil.json'
    if not file.is_file():
        if path:
            raise ValueError('Configuration file does not exist')
        return {}
    data = json.loads(file.read_text(encoding='utf-8'))
    fields = {'version', 'paths', 'mode', 'exclude', 'rules', 'html'}
    if not isinstance(data, dict) or set(data) - fields or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('Configuration requires version 1 and supported fields')
    for name in ('paths', 'exclude'):
        if name in data and (not isinstance(data[name], list) or any(not isinstance(v, str) or not v for v in data[name])):
            raise ValueError('Configuration paths/exclude must be lists of nonempty strings')
    if data.get('mode', 'auto') not in ('auto', 'logs', 'python'):
        raise ValueError('Configuration mode must be auto, logs or python')
    for name in ('rules', 'html'):
        if name in data and (not isinstance(data[name], str) or not data[name]):
            raise ValueError('Configuration rules/html must be nonempty paths')
    root = file.resolve().parent
    for name in ('rules', 'html'):
        if name in data:
            data[name] = str(root / data[name])
    if 'paths' in data:
        data['paths'] = [str(root / value) for value in data['paths']]
    data['_file'] = str(file.resolve())
    return data


def init_project():
    paths = [Path('logveil.json'), Path('logveil-rules.json')]
    if any(p.exists() for p in paths):
        raise ValueError('logveil.json or logveil-rules.json already exists; nothing changed')
    for path, data in zip(paths, (DEFAULT, {'version': 1, 'rules': []})):
        with path.open('x', encoding='utf-8') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
    return paths
