"""Multi-terminal interactive gateway and output stream paginator.

Features:
- Supports terminals 1 to 10 per authorized user.
- Dot command prefixes:
    - .stop: Interrupts running process and halts output streaming (Ctrl+C / SIGINT).
    - .new / .newterminal / .n: Allocates and switches to the next available terminal (1..10).
    - .t1 .. .t10 / .terminal1 .. .terminal10: Switches active terminal to the specified number.
    - .terminals / .list: Lists all open terminals and their running state.
    - .close / .close<N>: Closes a terminal session.
- Output pagination across multiple Telegram messages continuing from the break point.
"""

from __future__ import annotations

import asyncio
import html
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from src.executor.process import kill_process_tree

MAX_TERMINALS = 10
DEFAULT_CHUNK_CHARS = 3500


class TerminalState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"


@dataclass
class TerminalSession:
    """Represents an active virtual terminal session."""

    terminal_id: int
    state: TerminalState = TerminalState.IDLE
    current_job_id: str | None = None
    process: asyncio.subprocess.Process | None = None
    task: asyncio.Task | None = None
    stop_requested: bool = False
    cwd: Path = field(default_factory=Path.cwd)
    created_at: float = field(default_factory=time.monotonic)
    last_active_at: float = field(default_factory=time.monotonic)

    def request_stop(self) -> bool:
        """Trigger .stop (SIGINT / SIGTERM) on the running process."""
        self.stop_requested = True
        self.state = TerminalState.STOPPED
        if self.process and self.process.returncode is None:
            kill_process_tree(self.process.pid)
            return True
        return False


class TerminalGateway:
    """Manages virtual terminals (1 to 10) for an authorized administrator."""

    def __init__(self, user_id: int, default_work_dir: Path | None = None) -> None:
        self.user_id = user_id
        self.default_work_dir = default_work_dir or Path.cwd()
        self.active_terminal_id: int = 1
        self.terminals: dict[int, TerminalSession] = {
            1: TerminalSession(terminal_id=1, cwd=self.default_work_dir)
        }

    def get_active_terminal(self) -> TerminalSession:
        """Return the currently selected terminal."""
        if self.active_terminal_id not in self.terminals:
            self.terminals[self.active_terminal_id] = TerminalSession(
                terminal_id=self.active_terminal_id, cwd=self.default_work_dir
            )
        terminal = self.terminals[self.active_terminal_id]
        terminal.last_active_at = time.monotonic()
        return terminal

    def switch_terminal(self, terminal_id: int) -> tuple[bool, str]:
        """Switch active context to terminal ID (1 to 10)."""
        if not (1 <= terminal_id <= MAX_TERMINALS):
            return False, f"ID terminal không hợp lệ (cho phép từ 1 đến {MAX_TERMINALS})."

        if terminal_id not in self.terminals:
            self.terminals[terminal_id] = TerminalSession(
                terminal_id=terminal_id, cwd=self.default_work_dir
            )

        self.active_terminal_id = terminal_id
        self.terminals[terminal_id].last_active_at = time.monotonic()
        status = self.terminals[terminal_id].state.value
        return True, f"📟 Đã chuyển sang Terminal #{terminal_id} [Trạng thái: {status}]."

    def open_new_terminal(self) -> tuple[bool, int, str]:
        """Allocate the next available terminal number from 1 to 10."""
        for tid in range(1, MAX_TERMINALS + 1):
            if tid not in self.terminals:
                session = TerminalSession(terminal_id=tid, cwd=self.default_work_dir)
                self.terminals[tid] = session
                self.active_terminal_id = tid
                return True, tid, f"📟 Đã mở và chuyển đến Terminal mới #{tid}."

        return (
            False,
            0,
            f"⚠️ Đã đạt giới hạn tối đa {MAX_TERMINALS} terminals. Dùng .close [ID] để đóng bớt.",
        )

    def close_terminal(self, terminal_id: int | None = None) -> tuple[bool, str]:
        """Close a terminal session and stop any running process."""
        target_id = terminal_id if terminal_id is not None else self.active_terminal_id
        if target_id not in self.terminals:
            return False, f"Terminal #{target_id} không tồn tại."

        # Terminate any running process
        session = self.terminals.pop(target_id)
        session.request_stop()

        # Adjust active terminal
        if self.active_terminal_id == target_id:
            if self.terminals:
                self.active_terminal_id = min(self.terminals.keys())
            else:
                self.active_terminal_id = 1
                self.terminals[1] = TerminalSession(terminal_id=1, cwd=self.default_work_dir)

        return True, f"🗑️ Đã đóng Terminal #{target_id}. Terminal hiện tại: #{self.active_terminal_id}."

    def list_terminals(self) -> list[dict[str, Any]]:
        """Return status information for all open terminals."""
        res: list[dict[str, Any]] = []
        for tid in sorted(self.terminals.keys()):
            t = self.terminals[tid]
            res.append({
                "id": tid,
                "is_active": (tid == self.active_terminal_id),
                "state": t.state.value,
                "job_id": t.current_job_id,
                "elapsed": time.monotonic() - t.last_active_at,
            })
        return res


def parse_dot_command(raw_text: str) -> tuple[str, list[str]] | None:
    """Parse dot command prefix starting with a dot (.).

    Returns:
        (command_type, arguments) or None if not a dot command.
    """
    text = raw_text.strip()
    if not text.startswith("."):
        return None

    # Remove leading dot
    body = text[1:].strip()
    if not body:
        return None

    tokens = body.split()
    cmd = tokens[0].lower()
    args = tokens[1:]

    # 1. Stop command (.stop)
    if cmd == "stop":
        return "stop", args

    # 2. New terminal (.new, .newterminal, .n)
    if cmd in ("new", "newterminal", "n"):
        return "new", args

    # 3. Terminal switch (.t1 .. .t10, .terminal1 .. .terminal10)
    match_t = re.match(r"^(t|terminal)([1-9]|10)$", cmd)
    if match_t:
        target_id = match_t.group(2)
        return "switch", [target_id]

    if cmd in ("t", "terminal") and args:
        if args[0].isdigit():
            return "switch", [args[0]]

    # 4. List terminals (.terminals, .list)
    if cmd in ("terminals", "list"):
        return "list", args

    # 5. Close terminal (.close, .close1 .. .close10)
    match_close = re.match(r"^close([1-9]|10)?$", cmd)
    if match_close:
        target = match_close.group(1)
        close_args = [target] if target else args
        return "close", close_args

    return "unknown", [cmd]


def paginate_output(
    content: str,
    max_chunk_chars: int = DEFAULT_CHUNK_CHARS,
) -> list[str]:
    """Split long output into multiple messages continuing seamlessly from previous stops.

    Each chunk is wrapped in HTML <pre><code class="language-text">...</code></pre>
    with characters escaped for security.
    """
    if not content:
        return ["<code>[Không có dữ liệu đầu ra]</code>"]

    chunks: list[str] = []
    start = 0
    total_len = len(content)

    while start < total_len:
        end = min(start + max_chunk_chars, total_len)

        # If not at the end of text, attempt to break nicely on a newline
        if end < total_len:
            last_newline = content.rfind("\n", start, end)
            if last_newline != -1 and (last_newline - start) > (max_chunk_chars // 2):
                end = last_newline + 1

        chunk_text = content[start:end]
        escaped_chunk = html.escape(chunk_text, quote=True)

        prefix = ""
        suffix = ""
        if start > 0:
            prefix = "<i>[Tiếp tục phần trước...]</i>\n"
        if end < total_len:
            suffix = "\n<i>[Còn tiếp...]</i>"

        formatted_message = f"{prefix}<pre><code class='language-text'>{escaped_chunk}</code></pre>{suffix}"
        chunks.append(formatted_message)
        start = end

    return chunks
