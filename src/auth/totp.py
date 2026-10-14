"""TOTP second-factor authentication (RFC 6238).

Enforces:
- Verification using pyotp with at most 1 step clock drift (valid_window=1).
- Single-use code verification (replay defense).
- Account lockout after 5 consecutive failures with exponential backoff.
- Never logging or leaking the code or secret.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pyotp

from src.config import check_file_permissions

CODE_REGEX = re.compile(r"^\d{6}$")


class TOTPManager:
    """Manages offline TOTP secrets, replay prevention, and failure lockout."""

    def __init__(
        self,
        totp_dir: str | Path,
        max_drift_steps: int = 1,
        lockout_threshold: int = 5,
        base_lockout_seconds: float = 300.0,
        enforce_file_perms: bool = True,
    ) -> None:
        self.totp_dir = Path(totp_dir)
        self.max_drift_steps = max_drift_steps
        self.lockout_threshold = lockout_threshold
        self.base_lockout_seconds = base_lockout_seconds
        self.enforce_file_perms = enforce_file_perms

        # user_id -> failure_count
        self._consecutive_failures: dict[int, int] = {}
        # user_id -> locked_until_timestamp
        self._locked_until: dict[int, float] = {}
        # user_id -> dict[code, expiry_timestamp]
        self._used_codes: dict[int, dict[str, float]] = {}

    def get_secret(self, user_id: int) -> str | None:
        """Read the offline TOTP secret from <totp_dir>/<user_id>.secret."""
        secret_file = self.totp_dir / f"{user_id}.secret"
        if not secret_file.is_file():
            return None

        if self.enforce_file_perms:
            check_file_permissions(secret_file)

        secret = secret_file.read_text(encoding="utf-8").strip()
        return secret if secret else None

    def is_locked(self, user_id: int, current_time: float | None = None) -> tuple[bool, float]:
        """Check if an account is currently locked due to excessive failures.

        Returns:
            (is_locked, remaining_seconds)
        """
        now = time.time() if current_time is None else current_time
        locked_until = self._locked_until.get(user_id, 0.0)
        if now < locked_until:
            return True, locked_until - now
        return False, 0.0

    def record_failure(self, user_id: int, current_time: float | None = None) -> tuple[bool, float]:
        """Record a failed attempt. Lock account with exponential backoff if threshold met."""
        now = time.time() if current_time is None else current_time
        failures = self._consecutive_failures.get(user_id, 0) + 1
        self._consecutive_failures[user_id] = failures

        if failures >= self.lockout_threshold:
            # Exponential backoff: threshold -> 1x, threshold+1 -> 3x, threshold+2 -> 12x
            multiplier_exponent = min(failures - self.lockout_threshold, 4)
            duration = self.base_lockout_seconds * (3 ** multiplier_exponent)
            self._locked_until[user_id] = now + duration
            return True, duration

        return False, 0.0

    def record_success(self, user_id: int) -> None:
        """Reset consecutive failures upon successful authentication."""
        self._consecutive_failures.pop(user_id, None)
        self._locked_until.pop(user_id, None)

    def _cleanup_used_codes(self, user_id: int, now: float) -> None:
        """Prune expired used codes."""
        user_used = self._used_codes.get(user_id, {})
        valid_used = {c: exp for c, exp in user_used.items() if exp > now}
        self._used_codes[user_id] = valid_used

    def verify_code(
        self,
        user_id: int,
        code: str,
        current_time: float | None = None,
        secret_override: str | None = None,
    ) -> tuple[bool, str]:
        """Verify a TOTP code for the specified user.

        Returns:
            (is_valid, reason)
            Reasons: 'ok', 'invalid_format', 'account_locked', 'secret_not_found',
                     'code_already_used', 'invalid_code'
        """
        now = time.time() if current_time is None else current_time
        code = code.strip()

        # 1. Format validation (exactly 6 digits)
        if not CODE_REGEX.match(code):
            return False, "invalid_format"

        # 2. Check lockout
        locked, remaining = self.is_locked(user_id, now)
        if locked:
            return False, f"account_locked:{int(remaining)}"

        # 3. Retrieve secret
        secret = secret_override or self.get_secret(user_id)
        if not secret:
            return False, "secret_not_found"

        # 4. Check replay (code already used within drift window)
        self._cleanup_used_codes(user_id, now)
        if code in self._used_codes.get(user_id, {}):
            self.record_failure(user_id, now)
            return False, "code_already_used"

        # 5. Verify RFC 6238 TOTP
        try:
            totp = pyotp.TOTP(secret)
            dt_now = datetime.fromtimestamp(now, tz=timezone.utc)
            is_valid = totp.verify(code, for_time=dt_now, valid_window=self.max_drift_steps)
        except Exception:
            self.record_failure(user_id, now)
            return False, "invalid_code"

        if is_valid:
            # Mark code as used for the duration of the drift window (drift steps * 30s + safety buffer)
            window_duration = (self.max_drift_steps * 2 + 1) * 30.0 + 10.0
            if user_id not in self._used_codes:
                self._used_codes[user_id] = {}
            self._used_codes[user_id][code] = now + window_duration

            self.record_success(user_id)
            return True, "ok"

        # Verification failed
        is_now_locked, duration = self.record_failure(user_id, now)
        if is_now_locked:
            return False, f"account_locked:{int(duration)}"
        return False, "invalid_code"
