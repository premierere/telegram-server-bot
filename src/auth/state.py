"""Multi-step authentication state machine.

Manages user progression through:
1. UNAUTHENTICATED (awaiting /login <TOTP>)
2. AWAITING_USERNAME (TOTP verified, awaiting Linux username)
3. AWAITING_PASSWORD (awaiting Linux password, with 5-retry limit reverting to username)
4. AUTHENTICATED (active session, ready for terminal commands)
5. AWAITING_NEW_TERMINAL_PASSWORD (awaiting password for /new <username>)

Supports distinct /logout (reverts to AWAITING_USERNAME, preserving TOTP)
and /exit (reverts to UNAUTHENTICATED).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AuthStage(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AWAITING_USERNAME = "AWAITING_USERNAME"
    AWAITING_PASSWORD = "AWAITING_PASSWORD"
    AUTHENTICATED = "AUTHENTICATED"
    AWAITING_NEW_TERMINAL_PASSWORD = "AWAITING_NEW_TERMINAL_PASSWORD"


@dataclass
class UserAuthState:
    stage: AuthStage = AuthStage.UNAUTHENTICATED
    pending_username: str | None = None
    active_username: str | None = None
    password_failures: int = 0
    target_new_terminal_username: str | None = None


class AuthStateManager:
    """Tracks authentication stages and password retry loops in memory."""

    def __init__(self, max_password_retries: int = 5) -> None:
        self.max_password_retries = max_password_retries
        self._states: dict[int, UserAuthState] = {}

    def _get_or_create(self, user_id: int) -> UserAuthState:
        if user_id not in self._states:
            self._states[user_id] = UserAuthState()
        return self._states[user_id]

    def get_stage(self, user_id: int) -> AuthStage:
        return self._get_or_create(user_id).stage

    def set_stage(
        self,
        user_id: int,
        stage: AuthStage,
        pending_username: str | None = None,
        target_new_terminal_username: str | None = None,
    ) -> None:
        state = self._get_or_create(user_id)
        state.stage = stage
        if pending_username is not None:
            state.pending_username = pending_username
        if target_new_terminal_username is not None:
            state.target_new_terminal_username = target_new_terminal_username

    def get_pending_username(self, user_id: int) -> str | None:
        return self._get_or_create(user_id).pending_username

    def get_active_username(self, user_id: int) -> str | None:
        return self._get_or_create(user_id).active_username

    def get_target_new_terminal_username(self, user_id: int) -> str | None:
        return self._get_or_create(user_id).target_new_terminal_username

    def get_password_failures(self, user_id: int) -> int:
        return self._get_or_create(user_id).password_failures

    def record_password_failure(self, user_id: int) -> tuple[AuthStage, int]:
        """Record an incorrect password attempt.

        Returns (next_stage, current_attempt_count).
        If attempts >= max_password_retries, resets failures and reverts to AWAITING_USERNAME.
        """
        state = self._get_or_create(user_id)
        state.password_failures += 1

        if state.password_failures >= self.max_password_retries:
            attempts = state.password_failures
            state.password_failures = 0
            state.pending_username = None
            state.stage = AuthStage.AWAITING_USERNAME
            return AuthStage.AWAITING_USERNAME, attempts

        return AuthStage.AWAITING_PASSWORD, state.password_failures

    def reset_failures(self, user_id: int) -> None:
        state = self._get_or_create(user_id)
        state.password_failures = 0

    def complete_authentication(self, user_id: int, active_username: str) -> None:
        """Mark user as fully authenticated with active Linux username."""
        state = self._get_or_create(user_id)
        state.stage = AuthStage.AUTHENTICATED
        state.active_username = active_username
        state.pending_username = None
        state.password_failures = 0

    def logout_to_username(self, user_id: int) -> None:
        """User logs out of Linux account: resets active user and reverts to AWAITING_USERNAME (keeps TOTP)."""
        state = self._get_or_create(user_id)
        state.stage = AuthStage.AWAITING_USERNAME
        state.active_username = None
        state.pending_username = None
        state.password_failures = 0
        state.target_new_terminal_username = None

    def exit_to_unauthenticated(self, user_id: int) -> None:
        """User exits session completely: clears all state and requires TOTP again."""
        self._states[user_id] = UserAuthState()
