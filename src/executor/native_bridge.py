"""Bridge to native C/C++ or Rust server_executor.

Dispatches execution to the compiled native binary when available,
or falls back seamlessly to the Python asyncio ProcessExecutor.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from pathlib import Path
from typing import Any

from src.executor.process import ExecutionResult, ProcessExecutor


class NativeExecutionBridge:
    """Manages execution via compiled native binary with Python fallback."""

    def __init__(
        self,
        native_binary_path: str | Path | None = None,
        fallback_executor: ProcessExecutor | None = None,
    ) -> None:
        self.fallback = fallback_executor or ProcessExecutor()
        self.native_binary_path = self._resolve_native_binary(native_binary_path)

    def _resolve_native_binary(self, explicit_path: str | Path | None) -> Path | None:
        """Find executable binary in explicit path, bin/, or current directory."""
        candidates = []
        if explicit_path:
            candidates.append(Path(explicit_path))

        base_dir = Path(__file__).resolve().parent.parent.parent
        ext = ".exe" if os.name == "nt" else ""
        candidates.extend([
            base_dir / f"bin/server_executor{ext}",
            base_dir / f"src/native/server_executor{ext}",
        ])

        which_path = shutil.which("server_executor")
        if which_path:
            candidates.append(Path(which_path))

        for c in candidates:
            if c.is_file() and (os.access(c, os.X_OK) or os.name == "nt"):
                return c

        return None

    @property
    def is_native_available(self) -> bool:
        """True if the native binary is found and executable."""
        return self.native_binary_path is not None

    async def execute(
        self,
        argv: list[str] | None = None,
        shell_command: str | None = None,
        use_sudo: bool = False,
        timeout_seconds: float = 30.0,
        work_dir: str | Path | None = None,
    ) -> ExecutionResult:
        """Execute command via native engine if present, else fallback."""
        if not self.is_native_available:
            # Sudo handling in fallback executor
            actual_argv = list(argv) if argv is not None else None
            actual_shell = shell_command
            if use_sudo:
                if actual_argv:
                    actual_argv = ["sudo"] + actual_argv
                elif actual_shell:
                    actual_shell = f"sudo {actual_shell}"

            return await self.fallback.execute(
                argv=actual_argv,
                shell_command=actual_shell,
                timeout_seconds=timeout_seconds,
                work_dir=work_dir,
            )

        # Native binary invocation
        exec_args = [str(self.native_binary_path)]
        if shell_command is not None:
            exec_args.extend(["shell", shell_command])
        else:
            exec_args.extend(["restricted"] + (argv or []))

        if use_sudo:
            exec_args.append("--sudo")

        return await self.fallback.execute(
            argv=exec_args,
            timeout_seconds=timeout_seconds,
            work_dir=work_dir,
        )
