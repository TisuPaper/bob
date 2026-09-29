"""Fetch a bounded Docker log snapshot using the user's Docker CLI context."""
import re
from .runner import scan_command


def docker_command(container, *, tail='1000', since=None, until=None):
    if not isinstance(container, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', container):
        raise ValueError('Enter a valid Docker container name or ID')
    if not isinstance(tail, str) or (tail != 'all' and not re.fullmatch(r'[0-9]{1,10}', tail)):
        raise ValueError('Docker tail must be a nonnegative integer or all')
    command = ['docker', 'logs', '--tail', tail]
    for option, value in (('--since', since), ('--until', until)):
        if value is not None:
            if not isinstance(value, str) or not value or len(value) > 128 or any(c.isspace() or ord(c) < 32 for c in value):
                raise ValueError('Docker time filters must be timestamps or durations such as 1h')
            command.extend([option, value])
    command.append(container)
    return command


def scan_docker(container, *, tail='1000', since=None, until=None, timeout=60):
    findings, summary = scan_command(docker_command(container, tail=tail, since=since, until=until), timeout)
    for finding in findings:
        stream = finding['log'].strip('<>')
        finding['log'] = f'docker://{container}/{stream}'
    summary.update({'input_type': 'docker', 'container': container, 'tail': tail,
                    'since': since, 'until': until, 'containers_scanned': 1 if summary['command_exit_code'] == 0 else 0})
    return findings, summary
