"""In-memory session management.

Sessions are bound strictly to user_id, live entirely in RAM,
expire on idle timeout (10m) and absolute timeout (1h), and
are completely destroyed on /logout or process restart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class Session:
    """Represents an active in-memory user session."""

    user_id: int
    login_time: float
    last_activity_time: float
    idle_timeout_seconds: float = 600.0  # 10 minutes
    absolute_timeout_seconds: float = 3600.0  # 1 hour

    def is_valid(self, current_time: float | None = None) -> tuple[bool, str | None]:
        """Check if session is still valid.

        Returns:
            (is_valid, reason)
        """
        now = time.time() if current_time is None else current_time

        # Check absolute timeout first
        if now - self.login_time > self.absolute_timeout_seconds:
            return False, "absolute_timeout"

        # Check idle timeout
        if now - self.last_activity_time > self.idle_timeout_seconds:
            return False, "idle_timeout"

        return True, None

    def touch(self, current_time: float | None = None) -> None:
        """Update last activity timestamp."""
        self.last_activity_time = time.time() if current_time is None else current_time


class SessionManager:
    """Thread-safe and async-safe in-memory session manager."""

    def __init__(
        self,
        idle_timeout_seconds: float = 600.0,
        absolute_timeout_seconds: float = 3600.0,
    ) -> None:
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_timeout_seconds = absolute_timeout_seconds
        self._sessions: dict[int, Session] = {}

    def create_session(self, user_id: int, current_time: float | None = None) -> Session:
        """Create a new session for user, overwriting any previous session."""
        now = time.time() if current_time is None else current_time
        session = Session(
            user_id=user_id,
            login_time=now,
            last_activity_time=now,
            idle_timeout_seconds=self.idle_timeout_seconds,
            absolute_timeout_seconds=self.absolute_timeout_seconds,
        )
        self._sessions[user_id] = session
        return session

    def get_session(self, user_id: int, current_time: float | None = None) -> Session | None:
        """Retrieve valid session for user. If expired, automatically cleans it up."""
        now = time.time() if current_time is None else current_time
        session = self._sessions.get(user_id)
        if not session:
            return None

        is_valid, _ = session.is_valid(now)
        if not is_valid:
            self.destroy_session(user_id)
            return None

        return session

    def touch_session(self, user_id: int, current_time: float | None = None) -> bool:
        """Update activity timestamp for active session."""
        session = self.get_session(user_id, current_time)
        if session:
            session.touch(current_time)
            return True
        return False

    def destroy_session(self, user_id: int) -> bool:
        """Destroy an active session."""
        return self._sessions.pop(user_id, None) is not None

    def destroy_all(self) -> None:
        """Clear all sessions (e.g. at shutdown or restart)."""
        self._sessions.clear()
