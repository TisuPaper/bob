"""Scan a child process's stdout/stderr without persisting or echoing raw output."""
import os
import math
import queue
import signal
import subprocess
import threading
import time
from .scanner import MAX_LINE_BYTES, scan_line


def scan_command(command, timeout=300):
    if not command:
        raise ValueError('run requires a command after --')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be positive')
    events = queue.Queue(maxsize=32)
    stopped = threading.Event()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, start_new_session=os.name == 'posix')

    def put(event):
        while not stopped.is_set():
            try:
                events.put(event, timeout=.1)
                return
            except queue.Full:
                pass

    def reader(name, pipe):
        try:
            while not stopped.is_set():
                chunk = pipe.read1(65536)
                if not chunk:
                    break
                put((name, chunk))
        except OSError as error:
            put((name, error))
        finally:
            put((name, None))
            pipe.close()

    threads = [threading.Thread(target=reader, args=(name, pipe), daemon=True)
               for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr))]
    buffers = {'stdout': b'', 'stderr': b''}
    lines = {'stdout': 0, 'stderr': 0}
    findings, complete = [], set()
    deadline = time.monotonic() + timeout

    def consume(name, data):
        if len(data) > MAX_LINE_BYTES:
            raise ValueError('Command output line exceeds the 1 MiB limit; scan incomplete')
        lines[name] += 1
        findings.extend(scan_line(data.decode('utf-8-sig'), f'<{name}>', lines[name]))

    try:
        for thread in threads:
            thread.start()
        while len(complete) < 2:
            if time.monotonic() >= deadline:
                raise ValueError('Command timed out; scan incomplete')
            try:
                name, chunk = events.get(timeout=min(.1, max(.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if isinstance(chunk, Exception):
                raise chunk
            if chunk is None:
                if buffers[name]:
                    consume(name, buffers[name])
                buffers[name] = b''
                complete.add(name)
                continue
            buffers[name] += chunk
            while b'\n' in buffers[name]:
                line, buffers[name] = buffers[name].split(b'\n', 1)
                consume(name, line)
            if len(buffers[name]) > MAX_LINE_BYTES:
                raise ValueError('Command output line exceeds the 1 MiB limit; scan incomplete')
        try:
            code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ValueError('Command timed out; scan incomplete') from None
        return findings, {'files_scanned': 0, 'streams_scanned': 2, 'log_lines': sum(lines.values()),
                          'command_exit_code': code, 'skipped_files': 0}
    finally:
        stopped.set()
        # On POSIX, terminate descendants too if capture failed or was interrupted.
        if len(complete) < 2 or process.poll() is None:
            if os.name == 'posix':
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                process.kill()
        process.wait()
        for thread in threads:
            thread.join(timeout=1)
