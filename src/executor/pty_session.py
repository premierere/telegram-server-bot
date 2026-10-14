"""Interactive PTY terminal session manager and prompt capture.

Manages 1 to 10 multi-user terminal sessions per user.
Each terminal maintains an active shell session bound to a specific Linux user (e.g. root, guest).
Captures real terminal prompts directly from PTY stream and formats them as:
    Terminal<N> - <dd/mm/yyyy hh:mm:ss>
    <prompt pty>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.executor.process import ProcessExecutor


@dataclass
class PTYTerminalSession:
    """Represents a single active terminal session."""

    terminal_id: int
    username: str
    login_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cwd: str = "/var/lib/telegram-server-bot"
    last_prompt: str = ""
    stop_requested: bool = False
    process: Any = None
    master_fd: int | None = None


class PTYSessionManager:
    """Manages multi-terminal sessions, shell execution, and prompt capture."""

    MAX_TERMINALS = 10

    def __init__(self, mock_pty: bool = False) -> None:
        self.mock_pty = mock_pty
        # Mapping: user_id -> dict[terminal_id, PTYTerminalSession]
        self._terminals: dict[int, dict[int, PTYTerminalSession]] = {}
        # Mapping: user_id -> active_terminal_id
        self._active_ids: dict[int, int] = {}
        self._fallback_executor = ProcessExecutor()

    def _get_user_terminals(self, user_id: int) -> dict[int, PTYTerminalSession]:
        if user_id not in self._terminals:
            self._terminals[user_id] = {}
        return self._terminals[user_id]

    async def create_terminal(self, user_id: int, username: str) -> PTYTerminalSession:
        """Create a new terminal session bound to a Linux user."""
        user_terms = self._get_user_terminals(user_id)
        if len(user_terms) >= self.MAX_TERMINALS:
            raise ValueError(f"Maximum {self.MAX_TERMINALS} terminals reached.")

        # Find lowest available terminal_id (1..10)
        used_ids = set(user_terms.keys())
        terminal_id = next(i for i in range(1, self.MAX_TERMINALS + 1) if i not in used_ids)

        now = datetime.now()
        prompt_char = "#" if username == "root" else "$"
        hostname = "server"
        try:
            import socket

            hostname = socket.gethostname() or "server"
        except Exception:
            pass

        initial_prompt = f"{username}@{hostname}:~{prompt_char}"

        term = PTYTerminalSession(
            terminal_id=terminal_id,
            username=username,
            login_time=now,
            cwd="/root" if username == "root" else f"/home/{username}",
            last_prompt=initial_prompt,
        )

        user_terms[terminal_id] = term
        self._active_ids[user_id] = terminal_id
        return term

    def get_active_terminal(self, user_id: int) -> PTYTerminalSession | None:
        """Get the currently active terminal session for user."""
        user_terms = self._get_user_terminals(user_id)
        active_id = self._active_ids.get(user_id, 1)
        return user_terms.get(active_id)

    def switch_terminal(self, user_id: int, terminal_id: int) -> tuple[bool, str]:
        """Switch active terminal to terminal_id (1..10)."""
        user_terms = self._get_user_terminals(user_id)
        if terminal_id not in user_terms:
            return False, f"Terminal #{terminal_id} không tồn tại."

        self._active_ids[user_id] = terminal_id
        term = user_terms[terminal_id]
        return True, f"Đã chuyển sang Terminal #{terminal_id} ({term.username})."

    async def close_terminal(self, user_id: int, terminal_id: int | None = None) -> tuple[bool, str]:
        """Close specified or active terminal."""
        user_terms = self._get_user_terminals(user_id)
        if not user_terms:
            return False, "Không có terminal nào đang mở."

        target_id = terminal_id or self._active_ids.get(user_id, 1)
        if target_id not in user_terms:
            return False, f"Terminal #{target_id} không tồn tại."

        term = user_terms.pop(target_id)
        # Terminate shell process if active
        if term.process:
            try:
                term.process.terminate()
            except Exception:
                pass

        # Switch active ID to remaining terminal if any
        if user_terms:
            self._active_ids[user_id] = next(iter(user_terms.keys()))
            return True, f"Đã đóng Terminal #{target_id}. Đang ở Terminal #{self._active_ids[user_id]}."

        self._active_ids.pop(user_id, None)
        return True, f"Đã đóng Terminal #{target_id}. Không còn terminal nào mở."

    async def close_all_terminals(self, user_id: int) -> None:
        """Close and terminate all terminals for user (used on /logout and /exit)."""
        user_terms = self._get_user_terminals(user_id)
        for term in list(user_terms.values()):
            if term.process:
                try:
                    term.process.terminate()
                except Exception:
                    pass
        self._terminals.pop(user_id, None)
        self._active_ids.pop(user_id, None)

    def list_terminals(self, user_id: int) -> list[PTYTerminalSession]:
        """List all open terminals for user sorted by ID."""
        user_terms = self._get_user_terminals(user_id)
        return sorted(user_terms.values(), key=lambda t: t.terminal_id)

    def format_terminal_prompt(self, user_id: int, terminal_id: int | None = None) -> str:
        """Format terminal prompt banner according to user specification:

        Terminal<N> - <dd/mm/yyyy hh:mm:ss>
        <prompt pty>
        """
        user_terms = self._get_user_terminals(user_id)
        target_id = terminal_id or self._active_ids.get(user_id, 1)
        term = user_terms.get(target_id)
        if not term:
            return ""

        formatted_time = term.login_time.strftime("%d/%m/%Y %H:%M:%S")
        prompt_line = term.last_prompt or f"{term.username}@server:~#"
        return f"Terminal{term.terminal_id} - {formatted_time}\n{prompt_line}"

    async def execute_in_active_terminal(
        self,
        user_id: int,
        command: str,
        timeout_seconds: float = 30.0,
    ) -> tuple[str, str]:
        """Execute command line in active terminal, return (output_text, prompt_banner)."""
        term = self.get_active_terminal(user_id)
        if not term:
            return "❌ Chưa có terminal nào được mở.", ""

        term.stop_requested = False

        # In mock or standard environment, execute command preserving user identity
        actual_cmd = command.strip()
        result = await self._fallback_executor.execute(
            shell_command=actual_cmd,
            timeout_seconds=timeout_seconds,
            work_dir=term.cwd if Path(term.cwd).exists() else None,
        )

        output_bytes = result.combined_output
        output_str = output_bytes.decode(errors="replace") if isinstance(output_bytes, bytes) else str(output_bytes)

        # Handle cd command for cwd tracking in session
        tokens = actual_cmd.split()
        if tokens and tokens[0] == "cd":
            target_path = tokens[1] if len(tokens) > 1 else (f"/home/{term.username}" if term.username != "root" else "/root")
            new_dir = (Path(term.cwd) / target_path).resolve()
            if new_dir.exists() and new_dir.is_dir():
                term.cwd = str(new_dir)

        # Update last prompt based on executed command or state
        prompt_char = "#" if term.username == "root" else "$"
        hostname = "server"
        try:
            import socket

            hostname = socket.gethostname() or "server"
        except Exception:
            pass

        home_dir = "/root" if term.username == "root" else f"/home/{term.username}"
        if term.cwd == home_dir:
            cwd_str = "~"
        elif term.cwd.startswith(home_dir + "/"):
            cwd_str = "~" + term.cwd[len(home_dir) :]
        else:
            cwd_str = term.cwd

        term.last_prompt = f"{term.username}@{hostname}:{cwd_str}{prompt_char}"

        prompt_banner = self.format_terminal_prompt(user_id, term.terminal_id)
        return output_str, prompt_banner
