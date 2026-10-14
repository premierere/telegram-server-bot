"""Identity and Update filtering module.

Strictly enforces:
- Numeric user ID allowlist.
- Private chats only where chat_id == user_id.
- Explicit update types: only text messages and callback queries.
- Drop edited, forwarded, channel, group, and inline messages.
- Replay protection: drop messages older than max_message_age_seconds (default 60s).
- Silent drop for non-allowlisted senders with rate-limited audit logging.
"""

from __future__ import annotations

import time
from typing import Any, Callable

# Use constants to avoid hard dependency on telegram types during standalone unit testing
CHAT_TYPE_PRIVATE = "private"


class IdentityFilter:
    """Filters incoming Telegram updates before any handler or policy is executed."""

    def __init__(
        self,
        allowed_user_ids: list[int],
        max_message_age_seconds: int = 60,
        unknown_audit_cooldown_seconds: float = 60.0,
        audit_logger: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.allowed_user_ids: set[int] = set(allowed_user_ids)
        self.max_message_age_seconds = max_message_age_seconds
        self.unknown_audit_cooldown_seconds = unknown_audit_cooldown_seconds
        self.audit_logger = audit_logger
        self._unknown_sender_last_logged: dict[int, float] = {}

    def _should_audit_unknown_sender(self, user_id: int, now: float) -> bool:
        """Rate-limit audit logging for unknown senders to prevent log flooding."""
        last_time = self._unknown_sender_last_logged.get(user_id, 0.0)
        if now - last_time >= self.unknown_audit_cooldown_seconds:
            self._unknown_sender_last_logged[user_id] = now
            # Clean up old entries if cache grows
            if len(self._unknown_sender_last_logged) > 1000:
                cutoff = now - self.unknown_audit_cooldown_seconds
                self._unknown_sender_last_logged = {
                    uid: t for uid, t in self._unknown_sender_last_logged.items() if t > cutoff
                }
            return True
        return False

    def validate_update(self, update: Any, current_time: float | None = None) -> tuple[bool, str | None]:
        """Validate whether an update is authorized and should be processed.

        Returns:
            (is_valid, rejection_reason)
            When is_valid is False:
                - If reason == 'unknown_sender', caller MUST NOT reply (silent drop).
                - Other reasons can also be dropped or logged.
        """
        now = time.time() if current_time is None else current_time

        # 1. Reject unsupported update types (edited, channels, groups, inline queries)
        if getattr(update, "edited_message", None) is not None:
            return False, "edited_message"

        if getattr(update, "channel_post", None) is not None or getattr(update, "edited_channel_post", None) is not None:
            return False, "channel_post"

        if getattr(update, "inline_query", None) is not None or getattr(update, "chosen_inline_result", None) is not None:
            return False, "inline_query"

        # 2. Handle Text Messages
        message = getattr(update, "message", None)
        if message is not None:
            # Must be a text message
            text = getattr(message, "text", None)
            if not text:
                return False, "non_text_message"

            # Must not be a forwarded message
            if (
                getattr(message, "forward_origin", None) is not None
                or getattr(message, "forward_date", None) is not None
                or getattr(message, "forward_from", None) is not None
                or getattr(message, "forward_from_chat", None) is not None
            ):
                return False, "forwarded_message"

            # Sender user object must exist
            from_user = getattr(message, "from_user", None)
            if from_user is None or getattr(from_user, "id", None) is None:
                return False, "missing_from_user"

            sender_id = from_user.id
            if not isinstance(sender_id, int):
                return False, "invalid_user_id_type"

            # Chat type must be private
            chat = getattr(message, "chat", None)
            if chat is None or getattr(chat, "type", None) != CHAT_TYPE_PRIVATE:
                return False, "non_private_chat"

            # Chat ID must strictly equal sender User ID
            if getattr(chat, "id", None) != sender_id:
                return False, "chat_id_mismatch"

            # Check timestamp (stale message replay defense)
            msg_date = getattr(message, "date", None)
            if msg_date is not None:
                msg_timestamp = msg_date.timestamp() if hasattr(msg_date, "timestamp") else float(msg_date)
                age = now - msg_timestamp
                if age > self.max_message_age_seconds:
                    return False, "stale_message"
                # Reject future timestamps beyond 10s clock skew
                if age < -10.0:
                    return False, "future_message"

            # Check allowlist
            if sender_id not in self.allowed_user_ids:
                if self._should_audit_unknown_sender(sender_id, now) and self.audit_logger:
                    self.audit_logger({
                        "event_type": "unauthorized_access",
                        "user_id": sender_id,
                        "chat_id": getattr(chat, "id", None),
                        "message_id": getattr(message, "message_id", None),
                        "decision": "denied",
                        "reason": "unknown_sender",
                    })
                return False, "unknown_sender"

            return True, None

        # 3. Handle Callback Queries (for dangerous command confirmations)
        callback_query = getattr(update, "callback_query", None)
        if callback_query is not None:
            from_user = getattr(callback_query, "from_user", None)
            if from_user is None or getattr(from_user, "id", None) is None:
                return False, "missing_from_user"

            sender_id = from_user.id
            if not isinstance(sender_id, int):
                return False, "invalid_user_id_type"

            # Check allowlist
            if sender_id not in self.allowed_user_ids:
                if self._should_audit_unknown_sender(sender_id, now) and self.audit_logger:
                    self.audit_logger({
                        "event_type": "unauthorized_access",
                        "user_id": sender_id,
                        "decision": "denied",
                        "reason": "unknown_sender",
                    })
                return False, "unknown_sender"

            # Verify associated message is in a private chat with same ID
            cb_message = getattr(callback_query, "message", None)
            if cb_message is not None:
                cb_chat = getattr(cb_message, "chat", None)
                if cb_chat is not None:
                    if getattr(cb_chat, "type", None) != CHAT_TYPE_PRIVATE:
                        return False, "non_private_chat"
                    if getattr(cb_chat, "id", None) != sender_id:
                        return False, "chat_id_mismatch"

            return True, None

        # Any other update type
        return False, "unsupported_update_type"
