"""Confirmation management for dangerous shell commands.

Binds dangerous command confirmation requests to:
- A cryptographically random one-time nonce.
- SHA-256 hash of the exact command text.
- Authorized Telegram user ID and chat ID.
- Bot message ID containing the confirmation inline buttons.
- A 30-second expiry timeout.

Callbacks verify all fields strictly and consume the nonce immediately (single-use).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass


def compute_command_hash(command_text: str) -> str:
    """Compute deterministic SHA-256 hash of stripped command text."""
    return hashlib.sha256(command_text.strip().encode("utf-8")).hexdigest()


@dataclass
class PendingConfirmation:
    """State for an unconfirmed dangerous command awaiting user action."""

    nonce: str
    command_hash: str
    command_text: str
    user_id: int
    chat_id: int
    created_at: float
    message_id: int | None = None
    expiry_seconds: float = 30.0

    def is_expired(self, current_time: float | None = None) -> bool:
        """Check if 30-second confirmation window has elapsed."""
        now = time.time() if current_time is None else current_time
        return now > (self.created_at + self.expiry_seconds)


class ConfirmationManager:
    """Manages creation, verification, and consumption of dangerous command confirmations."""

    def __init__(self, default_expiry_seconds: float = 30.0) -> None:
        self.default_expiry_seconds = default_expiry_seconds
        self._pending: dict[str, PendingConfirmation] = {}

    def create_confirmation(
        self,
        user_id: int,
        chat_id: int,
        command_text: str,
        message_id: int | None = None,
        expiry_seconds: float | None = None,
        current_time: float | None = None,
    ) -> PendingConfirmation:
        """Create a new confirmation request with a cryptographically secure random nonce."""
        now = time.time() if current_time is None else current_time
        nonce = secrets.token_hex(16)
        cmd_hash = compute_command_hash(command_text)
        expiry = expiry_seconds if expiry_seconds is not None else self.default_expiry_seconds

        pending = PendingConfirmation(
            nonce=nonce,
            command_hash=cmd_hash,
            command_text=command_text.strip(),
            user_id=user_id,
            chat_id=chat_id,
            message_id=message_id,
            created_at=now,
            expiry_seconds=expiry,
        )
        self._pending[nonce] = pending
        return pending

    def set_message_id(self, nonce: str, message_id: int) -> bool:
        """Attach bot message ID after sending the confirmation inline keyboard."""
        pending = self._pending.get(nonce)
        if pending:
            pending.message_id = message_id
            return True
        return False

    def verify_and_consume(
        self,
        nonce: str,
        user_id: int,
        chat_id: int,
        message_id: int | None = None,
        command_text: str | None = None,
        current_time: float | None = None,
    ) -> tuple[bool, str | None, PendingConfirmation | None]:
        """Verify confirmation parameters and consume the nonce immediately (single-use).

        Returns:
            (success, error_reason, pending_confirmation)
        """
        now = time.time() if current_time is None else current_time

        # 1. Nonce lookup & immediate consumption (prevents replay or race condition)
        pending = self._pending.pop(nonce, None)
        if not pending:
            return False, "invalid_or_expired_nonce", None

        # 2. Expiry check
        if pending.is_expired(now):
            return False, "confirmation_expired", None

        # 3. User verification
        if pending.user_id != user_id:
            return False, "user_id_mismatch", None

        # 4. Chat verification
        if pending.chat_id != chat_id:
            return False, "chat_id_mismatch", None

        # 5. Message ID verification (if recorded)
        if pending.message_id is not None and message_id is not None:
            if pending.message_id != message_id:
                return False, "message_id_mismatch", None

        # 6. Command text / hash verification (if provided)
        if command_text is not None:
            expected_hash = compute_command_hash(command_text)
            if pending.command_hash != expected_hash:
                return False, "command_hash_mismatch", None

        return True, None, pending

    def cancel(self, nonce: str) -> bool:
        """Cancel and purge a pending confirmation."""
        return self._pending.pop(nonce, None) is not None
