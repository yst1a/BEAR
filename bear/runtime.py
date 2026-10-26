"""Single-design tool execution with explicit timeouts and local outputs."""
from pathlib import Path
import hashlib
import os
import shutil
import signal
import subprocess
import time

NATIVE = Path(os.environ.get('BEAR_WORK_DIR', '.bear-work')).resolve()
ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tool(name):
    override = os.environ.get('BEAR_' + name.upper().replace('-', '_'))
    return override or shutil.which(name) or name


def run_guarded(args, cwd=None, log=None, timeout=None, memory_mb=None,
                env=None, heavy=False, check=False, **kwargs):
    """Run once; return tool failure or timeout without retrying.

    memory_mb and heavy remain accepted for source API compatibility. They do
    not enforce memory limits or schedule resources.
    """
    cwd = Path(cwd or NATIVE).resolve()
    cwd.mkdir(parents=True, exist_ok=True)
    log = Path(log or cwd / 'tool.log').resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    args = list(map(str, args))
    timed = False
    preserve_group = os.name == 'posix' and os.environ.get('BEAR_PRESERVE_JOB_GROUP') == '1'
    try:
        with log.open('wb') as stream:
            process = subprocess.Popen(args, cwd=cwd, stdout=stream,
                                       stderr=subprocess.STDOUT,
                                       env={**ENV, **(env or {})},
                                       start_new_session=os.name == 'posix' and not preserve_group)
            try:
                process.wait(timeout=timeout or 3600)
            except subprocess.TimeoutExpired:
                if preserve_group:
                    # Keep all tools inside the caller's existing
                    # process group. On timeout, kill this tool's subtree only.
                    table = subprocess.check_output(['ps', '-eo', 'pid=,ppid='], text=True)
                    pairs = [tuple(map(int, line.split())) for line in table.splitlines() if line.strip()]
                    descendants = {process.pid}
                    while True:
                        grown = descendants | {child for child, parent in pairs if parent in descendants}
                        if grown == descendants:
                            break
                        descendants = grown
                    for pid in sorted(descendants, reverse=True):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                elif os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
                timed = True
        code = process.returncode
        pid = process.pid
    except OSError as error:
        log.write_text(str(error) + '\n', encoding='utf-8')
        code, pid = 127, None
    result = dict(returncode=code,
                  status='UNKNOWN_TIMEOUT' if timed else 'PASS' if code == 0 else 'UNKNOWN_TOOL_FAILURE',
                  stdout=log.read_text(encoding='utf-8', errors='replace'),
                  elapsed_s=time.monotonic() - started, log=str(log), pid=pid,
                  args=args, memory_limit_bytes=None)
    if check and code:
        raise RuntimeError(str(log))
    return result
