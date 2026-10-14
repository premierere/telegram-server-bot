"""Structured JSON Lines audit logger and admin security notifier.

Enforces:
- Append-only structured JSON lines log with strict file permissions (0600).
- Redaction of all secrets before writing.
- Duplicate output to stdout for systemd-journald capture.
- Real-time Telegram alerting to configured admin_user_ids on high-priority events:
    - Service start / shutdown
    - Successful logins
    - Account lockouts
    - Dangerous command confirmations
    - Sudo elevation requests
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine

from src.redaction import redact_secrets


@dataclass
class AuditEvent:
    """Represents a structured security audit event."""

    user_id: int
    event_type: str
    decision: str
    reason: str
    timestamp: str | None = None
    chat_id: int | None = None
    message_id: int | None = None
    command: str | None = None
    exit_code: int | None = None
    duration_ms: float | None = None
    output_size_bytes: int | None = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.command:
            self.command = redact_secrets(self.command)


class AuditLogger:
    """Manages append-only JSON Lines logging and admin alerts."""

    def __init__(
        self,
        audit_file_path: str | Path | None = None,
        echo_stdout: bool = True,
        admin_user_ids: list[int] | None = None,
        admin_notifier: Callable[[int, str], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        self.audit_file_path = Path(audit_file_path) if audit_file_path else None
        self.echo_stdout = echo_stdout
        self.admin_user_ids = set(admin_user_ids or [])
        self.admin_notifier = admin_notifier

        # Ensure audit log directory exists with safe permissions
        if self.audit_file_path:
            self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: AuditEvent) -> None:
        """Append event to structured log and stdout."""
        data = asdict(event)
        # Ensure no raw secrets leaked
        if data.get("command"):
            data["command"] = redact_secrets(data["command"])

        json_line = json.dumps(data, ensure_ascii=False)

        # 1. Write to append-only audit file
        if self.audit_file_path:
            file_exists = self.audit_file_path.exists()
            with open(self.audit_file_path, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")

            # Set 0600 permissions on new file on POSIX
            if not file_exists and os.name == "posix":
                try:
                    os.chmod(self.audit_file_path, 0o600)
                except OSError:
                    pass

        # 2. Output to stdout for systemd-journald
        if self.echo_stdout:
            sys.stdout.write(f"[AUDIT] {json_line}\n")
            sys.stdout.flush()

    async def notify_admins(self, message: str) -> None:
        """Send urgent security notification to all configured administrators."""
        if not self.admin_notifier or not self.admin_user_ids:
            return

        for admin_id in self.admin_user_ids:
            try:
                await self.admin_notifier(admin_id, message)
            except Exception as exc:
                sys.stderr.write(f"Failed to send admin notification to {admin_id}: {exc}\n")

    async def log_and_alert(self, event: AuditEvent, alert_message: str | None = None) -> None:
        """Log audit event and trigger Telegram alert if message provided."""
        self.log(event)
        if alert_message:
            await self.notify_admins(alert_message)
