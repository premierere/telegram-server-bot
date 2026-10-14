"""Subprocess execution with process group isolation, streaming output cap, and timeouts.

Enforces:
- Clean, allowlisted environment variables (no bot token, no credentials).
- Process group isolation (start_new_session=True).
- Stdin connected to /dev/null.
- Output capped during streaming (Option A: kill group when exceeding 1MB).
- Two-stage kill (SIGTERM, then SIGKILL after grace period) on timeout or abort.
- Fixed working directory.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Clean default environment allowlist
DEFAULT_ENV_ALLOWLIST = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "en_US.UTF-8",
    "LC_ALL": "en_US.UTF-8",
    "USER": "telegram-bot",
    "HOME": "/var/lib/telegram-server-bot",
}


@dataclass
class ExecutionResult:
    """Outcome of a process execution."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    duration_ms: float
    is_timeout: bool = False
    is_truncated: bool = False
    is_killed: bool = False

    @property
    def combined_output(self) -> bytes:
        """Combine stdout and stderr."""
        if self.stdout and self.stderr:
            return self.stdout + b"\n" + self.stderr
        return self.stdout or self.stderr


def build_sanitized_env(custom_overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a clean, sanitized environment dictionary from strict allowlist."""
    env = dict(DEFAULT_ENV_ALLOWLIST)

    # In testing on Windows or non-standard environments, inherit minimum system variables safely
    if os.name == "nt":
        for var in ("SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP"):
            if var in os.environ:
                env[var] = os.environ[var]
        if "PATH" in os.environ and "PATH" not in env:
            env["PATH"] = os.environ["PATH"]

    if custom_overrides:
        for k, v in custom_overrides.items():
            # Never allow tokens or secrets to be injected
            if any(secret in k.upper() for secret in ("TOKEN", "SECRET", "PASSWORD", "KEY")):
                continue
            env[k] = v

    # Explicitly ensure sensitive variables are NEVER present
    for secret_key in ("TELEGRAM_BOT_TOKEN", "BOT_TOKEN", "TOTP_SECRET", "CREDENTIALS_DIRECTORY"):
        env.pop(secret_key, None)

    return env


# Portability helper: SIGKILL exists on POSIX, fallback to SIGTERM on Windows
SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


def kill_process_tree(pid: int, sig: Any = signal.SIGTERM) -> None:
    """Kill entire process group or tree."""
    try:
        if os.name == "posix":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError):
                os.kill(pid, sig)
        else:
            # On Windows fallback
            os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass


class ProcessExecutor:
    """Executes subprocesses under strict isolation and resource boundaries."""

    def __init__(
        self,
        default_work_dir: str | Path | None = None,
        max_output_bytes: int = 1048576,  # 1 MB
        grace_period_seconds: float = 3.0,
    ) -> None:
        self.default_work_dir = Path(default_work_dir) if default_work_dir else Path.cwd()
        self.max_output_bytes = max_output_bytes
        self.grace_period_seconds = grace_period_seconds

    async def _kill_process_gracefully(self, process: asyncio.subprocess.Process) -> None:
        """Send SIGTERM to process group, wait grace period, then send SIGKILL."""
        if process.returncode is not None:
            return

        pid = process.pid
        # Stage 1: SIGTERM
        kill_process_tree(pid, signal.SIGTERM)

        try:
            await asyncio.wait_for(process.wait(), timeout=self.grace_period_seconds)
        except TimeoutError:
            # Stage 2: SIGKILL
            kill_process_tree(pid, SIGKILL)
            try:
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except Exception:
                pass

    async def _stream_capped_reader(
        self,
        stream: asyncio.StreamReader,
        output_buffer: bytearray,
        stop_event: asyncio.Event,
        chunk_size: int = 4096,
    ) -> bool:
        """Stream data from stream into buffer up to max_output_bytes.

        Returns:
            True if truncated (exceeded limit), False otherwise.
        """
        truncated = False
        while not stream.at_eof() and not stop_event.is_set():
            chunk = await stream.read(chunk_size)
            if not chunk:
                break

            current_len = len(output_buffer)
            if current_len + len(chunk) > self.max_output_bytes:
                allowed = self.max_output_bytes - current_len
                if allowed > 0:
                    output_buffer.extend(chunk[:allowed])
                output_buffer.extend(
                    b"\n[OUTPUT TRUNCATED: Exceeded 1MB stream limit - process terminated]"
                )
                truncated = True
                stop_event.set()
                break

            output_buffer.extend(chunk)

        return truncated

    async def execute(
        self,
        argv: list[str] | None = None,
        shell_command: str | None = None,
        timeout_seconds: float = 30.0,
        work_dir: str | Path | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Run command either via direct argv vector (restricted mode) or shell (shell mode).

        Exactly one of `argv` or `shell_command` must be provided.
        """
        if (argv is None and shell_command is None) or (argv is not None and shell_command is not None):
            raise ValueError("Provide exactly one of argv or shell_command.")

        cwd = Path(work_dir) if work_dir else self.default_work_dir
        if not cwd.exists():
            cwd.mkdir(parents=True, exist_ok=True)

        env = build_sanitized_env(env_overrides)
        start_time = time.monotonic()

        # Build subprocess creation kwargs
        kwargs: dict[str, Any] = {
            "stdin": asyncio.subprocess.DEVNULL,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "cwd": str(cwd),
            "env": env,
        }

        # Enable process group isolation
        if os.name == "posix":
            kwargs["start_new_session"] = True

        if argv is not None:
            process = await asyncio.create_subprocess_exec(*argv, **kwargs)
        else:
            # Shell mode explicitly uses /bin/bash -c on POSIX
            if os.name == "posix":
                process = await asyncio.create_subprocess_exec("/bin/bash", "-c", shell_command, **kwargs)
            else:
                process = await asyncio.create_subprocess_shell(shell_command, **kwargs)

        stdout_buf = bytearray()
        stderr_buf = bytearray()
        stop_event = asyncio.Event()

        is_timeout = False
        is_truncated = False

        # Read streams asynchronously while monitoring limits
        stdout_task = asyncio.create_task(
            self._stream_capped_reader(process.stdout, stdout_buf, stop_event)
        )
        stderr_task = asyncio.create_task(
            self._stream_capped_reader(process.stderr, stderr_buf, stop_event)
        )

        wait_proc_task = asyncio.create_task(process.wait())
        wait_stop_task = asyncio.create_task(stop_event.wait())

        done, pending = await asyncio.wait(
            [wait_proc_task, wait_stop_task],
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for p_task in pending:
            p_task.cancel()

        if not done:
            # Neither task completed -> execution timed out
            is_timeout = True
            await self._kill_process_gracefully(process)
        elif wait_stop_task in done and not wait_proc_task.done():
            # Stop event triggered (output cap exceeded or stop requested)
            is_truncated = True
            await self._kill_process_gracefully(process)

        # Wait for stream readers to wrap up
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        duration_ms = (time.monotonic() - start_time) * 1000.0
        exit_code = process.returncode if process.returncode is not None else -1

        return ExecutionResult(
            stdout=bytes(stdout_buf),
            stderr=bytes(stderr_buf),
            exit_code=exit_code,
            duration_ms=duration_ms,
            is_timeout=is_timeout,
            is_truncated=is_truncated,
            is_killed=is_timeout or is_truncated,
        )
